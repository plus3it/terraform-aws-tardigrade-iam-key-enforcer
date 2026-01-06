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

import sys
import csv
import io
from time import sleep


from argparse import ArgumentParser
from constants import LOG, SESSION
from aws_assume_role_lib import assume_role, generate_lambda_session_name
from iam_key_enforcer_report import EventDetails, IamKeyEnforcerReport
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
    event_details = EventDetails(
        event["account_number"],
        event["account_name"],
        event["email_targets"],
        event["email_user_enabled"],
        event["exempt_groups"],
    )
    main(
        event["role_arn"],
        event_details,
        context.function_name,
        event["armed"],
        event.get("debug"),
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


def main(role_arn, account_details, function_name, armed, is_debug):
    """Main handler for IAM Key Enforcer."""

    # Get IAM Client
    client_iam = get_client_iam(role_arn, function_name)

    # Get Credential Report
    credential_report = get_credential_report(client_iam, report_counter=0)

    enforcer_report = IamKeyEnforcerReport(
        client_iam, account_details, credential_report, armed, is_debug
    )

    enforcer_report.generate()


# Configure exception handler
sys.excepthook = exception_hook

# CLI Entry Point for Local Testing
if __name__ == "__main__":
    parser = ArgumentParser(
        description="Update a role trust policy in another account."
    )
    parser.add_argument(
        "--role-arn",
        required=True,
        help="ARN of the IAM role to assume in the target account (case sensitive)",
    )

    parser.add_argument(
        "--account-id",
        required=True,
        help="Account id of the target account to audit",
    )

    parser.add_argument(
        "--account-name",
        required=True,
        help="Account name of the target account to audit",
    )

    parser.add_argument(
        "--email-targets",
        required=True,
        help="Email to send admin report to",
    )

    parser.add_argument(
        "--exempt-groups",
        required=False,
        help="Group Names that are exempt from key enforcement actions",
    )

    args = parser.parse_args()
    account_details = EventDetails(
        account_id=args.account_id,
        account_name=args.account_name,
        email_targets=args.email_targets,
        email_user_enabled=False,
        exempt_groups=[],
    )
    sys.exit(main(args.role_arn, account_details, "iam_key_enforcer_cli", False, True))
