"""IAM Key Enforcer and Reporter."""

from dataclasses import dataclass
from datetime import datetime

import utils
from botocore.exceptions import ClientError
from constants import (
    DEFAULT_PROCESSING_ERROR_MSG,
    DELETE_ACTION,
    DISABLE_ACTION,
    EXEMPT_ACTION,
    KEY_AGE_DELETE,
    KEY_AGE_INACTIVE,
    KEY_AGE_WARNING,
    KEY_USE_THRESHOLD,
    LOG,
    NO_ACTION,
    S3_ENABLED,
    WARN_ACTION,
)
from errors import IamKeyEnforcerError, TemplateDataError
from iam_key_enforcement_report_row import IAMKeyReportRow
from mailers import (
    AdminMailer,
    UserMailer,
    get_user_email_from_tags,
    optional_email_template_data,
)


@dataclass
class IaMAccessKey:
    """IaM Access Key Data."""

    id: str
    age: int
    last_used_date: datetime | None
    boto_key: dict


@dataclass
class IaMAccessKeyUser:
    """IaM Access Key User Data."""

    name: str
    exempted: bool
    key: IaMAccessKey


class IamKeyEnforcerReporter:
    """IAM Key Enforcer Report Generation and Notification."""

    def __init__(self, client_iam, event: dict, log_prefix: str):
        """Create IAM Key Enforcer Reporter."""
        self.client_iam = client_iam
        self.log_prefix = log_prefix
        self.has_errors = False
        self.enforce_details = event

    def enforce(self, credentials_report):
        """Process Credentials, Enforce, and Report."""
        enforcement_report = self.enforce_and_report(credentials_report)

        if enforcement_report:
            # Get the admin email template data
            admin_template_data = self.admin_template_data(enforcement_report)
            # Mail the admin report
            self.mail_admin_report(admin_template_data)
            # Store the admin report in s3
            self.store_admin_report(admin_template_data)
        else:
            LOG.info(
                "No expiring access keys for account name %s - number %s",
                self.enforce_details["account_name"],
                self.enforce_details["account_number"],
            )

        if self.has_errors:
            raise IamKeyEnforcerError(DEFAULT_PROCESSING_ERROR_MSG)

    def enforce_and_report(self, credentials_report):
        """Process each user and key in the Credential Report."""
        # Initialize message content
        report_rows = []

        # Access the credential report and process it
        for row in credentials_report:
            try:
                user = row["user"]
                # Each row is a unique IAM user
                LOG.debug("Processing user: %s", user)

                # Skip processing the root account user
                if not utils.root_user(user):
                    user_report = self.process_user(user)
                    if user_report:
                        report_rows.append(user_report)
            except ClientError:
                self.error(f"Error processing user {user}, skipping user")
                continue

        return report_rows

    def process_user(self, user_name):
        """Process user accounts access keys if they exist."""
        # Test if user is in an exempted group
        exempted = utils.is_user_exempted(
            self.client_iam, user_name, self.enforce_details["exempt_groups"]
        )

        # List of iam enforcment report rows for user being processed
        user_report = []

        # Get Access Keys for user
        access_keys = utils.get_user_access_keys(self.client_iam, user_name)

        for access_key in access_keys:
            try:
                access_key_id = access_key["AccessKeyId"]
                key_age = utils.object_age(access_key["CreateDate"])
                last_used_date = utils.get_key_last_used_date(
                    self.client_iam, access_key_id
                )

                key = IaMAccessKey(access_key_id, key_age, last_used_date, access_key)
                user = IaMAccessKeyUser(user_name, exempted, key)

                # Log Access Key Details
                LOG.info(
                    "User Key Details: %s \t %s \t %s \t %s \t %s",
                    user.name,
                    user.key.id,
                    str(user.key.age),
                    user.key.boto_key["Status"],
                    str(user.key.last_used_date),
                )
                key_report_row = self.process_user_access_key(user)

                if key_report_row:
                    user_report.append(
                        report_row_details(key_report_row, key_age, last_used_date)
                    )

            except ClientError:
                self.error()
                continue

        return user_report

    def process_user_access_key(self, key_user):
        """Process each access key for a user."""
        access_key_id = key_user.key.id

        action = get_enforcement_action(
            key_user.exempted, key_user.key.last_used_date, key_user.key.age
        )

        if action == NO_ACTION:
            return None

        status = self.enforce_action(action, key_user)

        enforcement_report_row = IAMKeyReportRow(
            key_user.name, access_key_id, action, status
        )

        # Send emails to user if an action was taken that requires notification
        if action in (DELETE_ACTION, DISABLE_ACTION):
            self.mail_user_key_report(action, key_user)

        return enforcement_report_row

    def enforce_action(self, action, key_user):
        """Enforce action on the specified key and returns the key status."""
        try:
            key_id = key_user.key.id
            user_name = key_user.name
            key_status = key_user.key.boto_key["Status"]
            LOG.info(
                "%s %s AccessKeyId %s for user %s (key age %s days : key status %s)",
                self.enforce_details["log_prefix"],
                action,
                key_id,
                user_name,
                key_user.key.age,
                key_status,
            )
            if action == DELETE_ACTION:
                self.delete_access_key(key_id, user_name)
                return "DELETED"

            if action == DISABLE_ACTION:
                self.disable_access_key(key_user.key.id, key_user.name)
                return key_user.key.boto_key["Status"]

            if action == EXEMPT_ACTION:
                return f"{key_status} (Exempt)"

            if action in (WARN_ACTION):
                return key_status

            LOG.error("Unknown action %s for key %s user %s", action, key_id, user_name)
            return f"{key_status} ({action} Error)"

        except ClientError:
            # Mark that an error has occurred and set the status as an action error
            self.error()
            return f'{key_user.key.boto_key["Status"]} ({action} Error)'

    def delete_access_key(self, access_key_id, user_name):
        """Delete Access Key."""
        if self.enforce_details["armed"]:
            self.client_iam.delete_access_key(
                UserName=user_name, AccessKeyId=access_key_id
            )

    def disable_access_key(self, access_key_id, user_name):
        """Disable Access Key."""
        if self.enforce_details["armed"]:
            self.client_iam.update_access_key(
                UserName=user_name, AccessKeyId=access_key_id, Status="Inactive"
            )

    def mail_user_key_report(self, action, key_user):
        """Send the user an email for the action performed."""
        try:
            if self.enforce_details["email_user_enabled"]:
                user_name = key_user.name

                armed_state_msg = utils.action_armed_state_message(
                    action, self.enforce_details["armed"]
                )
                if armed_state_msg:
                    template_data = self.user_email_template_data(key_user, action)
                    tags = self.client_iam.list_user_tags(UserName=user_name)
                    user_email_addr = get_user_email_from_tags(
                        user_name, tags, self.enforce_details["is_debug"]
                    )
                    user_mailer = UserMailer(
                        self.enforce_details["email_targets"],
                        user_email_addr,
                        template_data,
                        self.enforce_details["is_debug"],
                    )
                    user_mailer.mail()
                else:
                    self.error(
                        (
                            f"Error Armed State Message - Action {action},"
                            f"User {user_name}, Key {key_user.key.id}, No Email Sent"
                        )
                    )
            else:
                LOG.info(
                    "Emailing the User is not enabled "
                    "per event 'email_user_enabled' variable setting"
                )
        except ClientError:
            self.error()

    def mail_admin_report(self, admin_template_data):
        """Create Admin Mailer and mail report."""
        try:
            admin_mailer = AdminMailer(
                self.enforce_details["email_targets"],
                admin_template_data,
                self.enforce_details["is_debug"],
            )
            admin_mailer.mail()
        except ClientError:
            self.error()

    def store_admin_report(self, template_data):
        """Store email report in S3 Bucket."""
        if not S3_ENABLED:
            LOG.info("S3 report not enabled per setting")
            return
        try:
            utils.store_in_s3(self.enforce_details["account_number"], template_data)
        except (ClientError, TemplateDataError):
            self.error()

    def admin_template_data(self, enforcer_report):
        """Build admin template data."""
        template_data = {
            "account_number": self.enforce_details["account_number"],
            "account_name": self.enforce_details["account_name"],
            "key_report_contents": enforcer_report,
            "key_age_inactive": KEY_AGE_INACTIVE,
            "key_age_delete": KEY_AGE_DELETE,
            "key_age_warning": KEY_AGE_WARNING,
            "key_use_threshold": KEY_USE_THRESHOLD,
        }
        template_data.update(
            optional_email_template_data(
                self.enforce_details["armed"],
                exempt_groups_string(self.enforce_details["exempt_groups"]),
            )
        )
        return template_data

    def user_email_template_data(self, key_user, action):
        """Build email template data for user emails."""
        armed = self.enforce_details["armed"]
        armed_state_msg = utils.action_armed_state_message(action, armed)

        template_data = {
            "armed_state_msg": armed_state_msg,
            "access_key_id": key_user.key.id,
            "action": action,
            "key_age": key_user.key.id,
            "user_name": key_user.name,
        }
        template_data.update(optional_email_template_data(armed))
        return template_data

    def error(self, msg=None):
        """Set has_errors to True and optionally LOG error message."""
        self.error()
        if msg:
            LOG.error(msg)


def get_enforcement_action(exempted, last_used_date, key_age):
    """Get the action to perform based on the keys usage and exemption status."""
    if not exempted and not last_used_date and key_age >= KEY_USE_THRESHOLD:
        # Not Exempted and Key has not been used and
        # is older than the usage threshold, delete and report
        return DELETE_ACTION

    if key_age < KEY_AGE_WARNING:
        # Key age is < warning, do nothing, continue
        return NO_ACTION

    if exempted:
        # EXEMPT:, do not take action on key, but report it
        return EXEMPT_ACTION

    if key_age >= KEY_AGE_DELETE:
        # NOT EXEMPT: Key is older than the age to delete
        # Attempt to delete and add row to report
        return DELETE_ACTION

    if key_age >= KEY_AGE_INACTIVE:
        # NOT EXEMPT: Key is older than the age to disable
        # Attempt to disable and add row to report
        return DISABLE_ACTION

    return WARN_ACTION


def report_row_details(key_report_row, key_age, last_used_date):
    """Get the key enforce report details as a dict."""
    return {
        "bg_color": key_report_row.get_row_bg_color(),
        "user_name": key_report_row.user_name,
        "access_key_id": key_report_row.access_key_id,
        "key_age": str(key_age),
        "key_status": key_report_row.status,
        "last_used_date": str(last_used_date),
    }


def exempt_groups_string(exempt_groups):
    """Get Exempt Groups as a commas separated string."""
    return ", ".join(exempt_groups) if exempt_groups else None
