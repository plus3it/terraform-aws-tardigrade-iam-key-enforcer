"""Utilities Module."""

import json
from datetime import UTC, datetime

import dateutil
from aws_manager import AWSClientManager
from constants import (
    DELETE_ACTION,
    DISABLE_ACTION,
    EMAIL_ADMIN_TEMPLATE,
    LOG,
    S3_BUCKET,
)
from errors import TemplateDataError


def get_key_last_used_date(client_iam, access_key_id) -> datetime | None:
    """Get the last used date for an access key as datetime.datetime."""
    # get time of last key use
    response = client_iam.get_access_key_last_used(AccessKeyId=access_key_id)
    # last_used_date value will not exist if key not used
    return response["AccessKeyLastUsed"].get("LastUsedDate")


def is_user_exempted(client_iam, user_name, exempt_groups) -> bool:
    """Determine if user is in an exempted group."""
    if exempt_groups:
        groups = client_iam.list_groups_for_user(UserName=user_name)
        for group in groups["Groups"]:
            if group["GroupName"] in exempt_groups:
                LOG.info(
                    "User is exempt via group membership in: %s",
                    group["GroupName"],
                )
                return True
    return False


def get_user_access_keys(client_iam, user_name) -> list[dict]:
    """Get Access Keys for a user."""
    access_keys = client_iam.list_access_keys(UserName=user_name)
    return access_keys["AccessKeyMetadata"]


def object_age(last_changed) -> int:
    """Calculate the object age in days since last change."""
    # Handle as string
    if isinstance(last_changed, str):
        last_changed_date = dateutil.parser.parse(last_changed).date()
    # Handle as native datetime
    elif isinstance(last_changed, datetime):
        last_changed_date = last_changed.date()
    else:
        return 0
    age = datetime.now(tz=UTC).date() - last_changed_date
    return age.days


def store_in_s3(account_number, template_data) -> None:
    """Store email report in S3 Bucket."""
    # Get the AWS CLients Manager (Singleton)
    aws_manager = AWSClientManager()
    s3_key = (
        f"{account_number}/access_key_audit_report_{datetime.now(tz=UTC).date()!s}.html"
    )

    response = aws_manager.ses.test_render_template(
        TemplateName=EMAIL_ADMIN_TEMPLATE,
        TemplateData=json.dumps(template_data),
    )

    email_contents = response.get("RenderedTemplate", None)

    if email_contents:
        LOG.debug(
            "Storing report to S3 key %s Report Details: %s",
            s3_key,
            email_contents,
        )
        aws_manager.s3.put_object(
            Bucket=S3_BUCKET,
            Key=s3_key,
            Body=email_contents,
        )
    else:
        err = f"Invalid template data for {account_number}"
        raise TemplateDataError(err)


def root_user(user) -> bool:
    """Check if the user is the root account."""
    if user == "<root_account>":
        LOG.debug("Skipping root account user: %s", user)
        return True
    return False


def action_armed_state_message(action, is_armed) -> str | None:
    """Return message based on action and armed state."""
    if action == DELETE_ACTION:
        return "has been deleted" if is_armed else "would be marked for deletion"

    if action == DISABLE_ACTION:
        return (
            "has been marked 'Inactive'" if is_armed else "would be marked 'Inactive'"
        )

    return None
