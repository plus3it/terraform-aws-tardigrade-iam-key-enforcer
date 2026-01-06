import datetime
import dateutil
import os
import json
from iam_key_enforcer import LOG
from botocore.exceptions import ClientError

from constants import CLIENT_SES, CLIENT_S3, EMAIL_ADMIN_TEMPLATE, S3_BUCKET

EMAIL_SOURCE = os.environ.get("EMAIL_SOURCE")


def get_key_last_used_date(client_iam, access_key_id, user_name):
    """Get the last used date for an access key."""
    try:
        # get time of last key use
        response = client_iam.get_access_key_last_used(AccessKeyId=access_key_id)
        # last_used_date value will not exist if key not used
        return response["AccessKeyLastUsed"].get("LastUsedDate")
    except ClientError as error:
        LOG.exception(
            "Error %s getting last used date for key %s user %s - skipping key",
            error.response["Error"]["Code"],
            access_key_id,
            user_name,
        )
        raise error


def is_user_exempted(client_iam, user_name, exempted_groups):
    """Determine if user is in an exempted group."""
    try:
        groups = client_iam.list_groups_for_user(UserName=user_name)
        for group in groups["Groups"]:
            if group["GroupName"] in exempted_groups:
                LOG.info(
                    "User is exempt via group membership in: %s", group["GroupName"]
                )
                return True
        return False
    except ClientError as error:
        LOG.exception(
            "Error %s checking if user is exempted - skipping user %s",
            error.response["Error"]["Code"],
            user_name,
        )
        raise error


def get_user_access_keys(client_iam, user_name):
    """Get Access Keys for a user."""
    try:
        access_keys = client_iam.list_access_keys(UserName=user_name)
        return access_keys["AccessKeyMetadata"]
    except ClientError as error:
        LOG.exception(
            "Error %s listing access keys for user %s - skipping user",
            error.response["Error"]["Code"],
            user_name,
        )
        raise error


def object_age(last_changed):
    """Determine days since last change."""
    # Handle as string
    if isinstance(last_changed, str):
        last_changed_date = dateutil.parser.parse(last_changed).date()
    # Handle as native datetime
    elif isinstance(last_changed, datetime.datetime):
        last_changed_date = last_changed.date()
    else:
        return 0
    age = datetime.date.today() - last_changed_date
    return age.days


def send_email(template, template_data, email_targets):
    """Email user with the action taken on their key."""
    return CLIENT_SES.send_templated_email(
        Source=EMAIL_SOURCE,
        Destination={
            "ToAddresses": email_targets,
        },
        Template=template,
        TemplateData=json.dumps(template_data),
    )


def store_in_s3(account_number, template_data):
    """Store email report in S3 Bucket."""
    s3_key = (
        f"{account_number}"
        "/access_key_audit_report_"
        f"{str(datetime.date.today())}.html"
    )

    response = CLIENT_SES.test_render_template(
        TemplateName=EMAIL_ADMIN_TEMPLATE, TemplateData=json.dumps(template_data)
    )

    email_contents = response.get("RenderedTemplate", None)

    if email_contents:
        LOG.debug(
            "Storing report to S3 key %s Report Details: %s", s3_key, email_contents
        )
        response = CLIENT_S3.put_object(
            Bucket=S3_BUCKET, Key=s3_key, Body=email_contents
        )
    else:
        raise TemplateDataError(
            "Error generating S3 report using TemplateName: %s and TemplateData: %s",
            EMAIL_ADMIN_TEMPLATE,
            template_data,
        )
