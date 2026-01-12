"""Audit Access Key Age.

Purpose:
    Reads the credential report:
    - Determines the age of each access key
    - Builds a report of all keys older than KEY_AGE_WARNING
    - Takes action (inactive/delete) on non-compliant Access Keys
Permissions:
    iam:GetCredentialReport
    iam:GetAccessKeyLastUsed
    iam:ListAccessKeys
    iam:ListGroupsForUser
    s3:putObject
    ses:SendEmail
    ses:SendRawEmail
Environment Variables:
    LOG_LEVEL: (optional): sets the level for function logging
            valid input: critical, error, warning, info (default), debug
    EMAIL_ADMIN_REPORT_ENABLED: used to enable or disable the SES emailed report
    EMAIL_SOURCE: send from address for the email, authorized in SES
    EMAIL_USER_TEMPLATE: Name of the SES template for user emails
    EMAIL_ADMIN_TEMPLATE: Name of the SES template for admin emails
    KEY_AGE_DELETE: age at which a key should be deleted (e.g. 120)
    KEY_AGE_INACTIVE: age at which a key should be inactive (e.g. 90)
    KEY_AGE_WARNING: age at which to warn (e.g. 75)
    KEY_USE_THRESHOLD: age at which unused keys should be deleted (e.g.30)
    S3_ENABLED: set to "true" and provide S3_BUCKET if the audit report
            should be written to S3
    S3_BUCKET: bucket name to write the audit report to if S3_ENABLED is
            set to "true"
Event Variables:
    armed: Set to "true" to take action on keys;
            "false" limits to reporting
    role_arn: Arn of role to assume
    account_name: AWS Account (friendly) Name
    account_number: AWS Account Number
    email_user_enabled: used to enable or disable the SES emailed report
    email_targets: default email address if event fails to pass a valid one
    exempt_groups: IAM Groups that are exempt from actions on access keys

"""

import re
import sys
import csv
import io

from argparse import ArgumentParser, ArgumentTypeError
from time import sleep
from constants import LOG, SESSION
from aws_assume_role_lib import assume_role, generate_lambda_session_name
from iam_key_enforcer_reporter import IamKeyEnforcerReporter
from errors import GenerateCredentialReportThrottleError


def exception_hook(exc_type, exc_value, exc_traceback):
    """Log all exceptions with hook for sys.excepthook."""
    LOG.exception(
        "%s: %s",
        exc_type.__name__,
        exc_value,
        exc_info=(exc_type, exc_value, exc_traceback),
    )


@LOG.inject_lambda_context(log_event=True)
def lambda_handler(event, context):  # pylint: disable=unused-argument
    """Audit Access Key Age.

    Reads the credential report:
        - Determines the age of each access key
        - Builds a report of all keys older than KEY_AGE_WARNING
        - Takes action (inactive/delete) on non-compliant Access Keys
    """
    # Call main function to peform the work
    main(
        event["role_arn"],
        event,
        context.function_name,
    )


def generate_credential_report(client_iam, report_counter, max_attempts=5):
    """Generate IAM Credential Report."""
    generate_report = client_iam.generate_credential_report()

    if generate_report["State"] == "COMPLETE":
        # Report is generated, proceed in Handler
        return None

    # Report is not ready, try again
    report_counter += 1
    LOG.info("Generate credential report count %s", report_counter)
    if report_counter < max_attempts:
        LOG.info("Still waiting on report generation")
        sleep(10)
        return generate_credential_report(client_iam, report_counter)

    throttle_error = "Credential report generation throttled - exit"
    raise GenerateCredentialReportThrottleError(throttle_error)


def get_credential_report(client_iam, report_counter=0):
    """Generate and Return IAM Credential Report."""
    generate_credential_report(client_iam, report_counter)

    # Get and parse the generated credential report
    credential_report = client_iam.get_credential_report()
    credential_report_csv = io.StringIO(credential_report["Content"].decode("utf-8"))
    return list(csv.DictReader(credential_report_csv))


def get_client_iam(role_arn, function_name):
    """Get boto3 IAM Client by Assuming the Role ARN and returning the client."""
    assumed_role_session = assume_role(
        SESSION, role_arn, RoleSessionName=generate_lambda_session_name(function_name)
    )
    return assumed_role_session.client("iam")


def main(role_arn, event, function_name):
    """Run the IAM Key Enforcer."""
    # Get IAM Client
    client_iam = get_client_iam(role_arn, function_name)

    # Get Credential Report
    credential_report = get_credential_report(client_iam, report_counter=0)

    # Create Iam Key Enforcer Report Object
    enforcer_reporter = IamKeyEnforcerReporter(client_iam, event)

    # Evaluate each user in the credential report and enforce key policies
    enforcer_reporter.enforce(credential_report)


# Configure exception handler
sys.excepthook = exception_hook


def account_number(value: str) -> str:
    """Argparse Account Number Validator."""
    if len(value) != 12 or not value.isdigit():
        raise ArgumentTypeError(
            "account number must be exactly 12 digits (leading zeros allowed)"
        )
    return value


def iam_role_arn(role_arn: str) -> str:
    """Argparse IAM Role Arn Validator."""
    iam_role_pattern = re.compile(
        r"^arn:"
        r"(?P<partition>aws|aws-us-gov)"
        r":iam::"
        r"(?P<account_id>\d{12})"
        r":role/"
        r"(?P<role_path>(?:[\w+=,.@-]+/)*[\w+=,.@-]+)$"
    )
    if not iam_role_pattern.match(role_arn):
        raise ArgumentTypeError(
            "invalid IAM role ARN "
            "expected: arn:aws|aws-us-gov:iam::<12-digit-account>:role/<role-name>)"
        )
    return role_arn


# CLI Entry Point for Local Testing
if __name__ == "__main__":
    parser = ArgumentParser(
        description="Update a role trust policy in another account."
    )
    parser.add_argument(
        "--role-arn",
        type=iam_role_arn,
        required=True,
        help="AWS ARN of the IAM role to assume in the target account (case sensitive)",
    )

    parser.add_argument(
        "--account-number",
        type=account_number,
        required=True,
        help="AWS Account number (12 digits) of the target account to audit",
    )

    parser.add_argument(
        "--account-name",
        required=True,
        type=str,
        help="AWS Account name of the target account to audit",
    )

    parser.add_argument(
        "--email-targets",
        required=True,
        nargs="+",
        type=str,
        help="Email to send admin report to",
    )

    parser.add_argument(
        "--exempt-groups",
        required=False,
        nargs="+",
        type=str,
        help="Group Names that are exempt from key enforcement actions",
    )

    parser.add_argument(
        "--email-user-enabled",
        action="store_true",
        help="Enable emailing the user",
    )

    parser.add_argument(
        "--armed",
        action="store_true",
        help="Arm the enforcer",
    )

    parser.add_argument(
        "--debug",
        action="store_true",
        help="Debug mode for emails (aka look for but don't add user emails)",
    )

    args = parser.parse_args()
    cli_enforce_details = {
        "account_name": args.account_name,
        "account_number": args.account_number,
        "armed": args.armed,
        "email_user_enabled": args.email_user_enabled,
        "email_targets": args.email_targets,
        "exempt_groups": args.exempt_groups,
        "is_debug": args.debug,
    }

    sys.exit(main(args.role_arn, cli_enforce_details, "iam_key_enforcer_cli"))
