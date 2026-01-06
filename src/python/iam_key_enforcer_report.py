"""Generates and Emails the IAM Key Enforcer Report fom the provided credential Report."""

import re
from time import sleep


from errors import IamKeyEnforcerError, IamKeyEnforcerEmailError
import utils as utils
from constants import (
    ADMIN_EMAIL,
    ARMED_PREFIX,
    DEFAULT_PROCESSING_ERROR_MSG,
    EMAIL_ADMIN_REPORT_ENABLED,
    EMAIL_ADMIN_TEMPLATE,
    EMAIL_BANNER_MSG,
    EMAIL_BANNER_MSG_COLOR,
    EMAIL_REGEX,
    EMAIL_TAG,
    EMAIL_USER_TEMPLATE,
    KEY_AGE_DELETE,
    KEY_AGE_INACTIVE,
    KEY_AGE_WARNING,
    KEY_USE_THRESHOLD,
    LOG,
    NOT_ARMED_PREFIX,
    S3_BUCKET,
    S3_ENABLED,
)
from botocore.exceptions import ClientError
from iam_key_enforcement_report_row import ROW_BG_COLORS, IAMKeyReportRow
from iam_key_enforcement_report_row import (
    DELETE_ACTION,
    DISABLE_ACTION,
    EXEMPT_ACTION,
    WARN_ACTION,
)


class EventDetails:
    """Event Details for the Account"""

    def __init__(
        self,
        account_id,
        account_name,
        email_targets,
        email_user_enabled,
        exempt_groups,
    ):
        self.accont_id = account_id
        self.account_name = account_name
        self.email_targets = email_targets
        self.email_used_enabled = email_user_enabled
        self.exempt_groups = exempt_groups


class IamKeyEnforcerReport:
    """IAM Key Enforcer Report Generation and Notification"""

    def __init__(self, client_iam, event_details, credentials_report, armed, is_debug):
        self.client_iam = client_iam
        self.event_details = event_details
        self.credentials_report = credentials_report
        self.armed = armed
        self.is_debug = is_debug
        self.has_errors = False

    def generate(self):
        """Generate the IAM Key Enforcer Report and send emails as needed."""

        enforcer_report = self.create_enforcer_report()

        if enforcer_report:
            exempt_groups = (
                ", ".join(self.event_details.exempt_groups)
                if self.event_details.exempt_groups
                else None
            )

            admin_template_data = get_admin_email_template_data(
                enforcer_report,
                self.event_details.account_number,
                self.event_details.account_name,
                self.armed,
                exempt_groups,
            )

            email_admin_report(
                self.event_details.email_targets, admin_template_data, self.is_debug
            )

            store_admin_report(self.event_details.account_number, admin_template_data)
        else:
            LOG.info(
                "No expiring access keys for account arn %s",
                self.event_details.account_name,
            )

        if self.has_errors:
            raise IamKeyEnforcerError(DEFAULT_PROCESSING_ERROR_MSG)

    def create_enforcer_report(self):
        """Process each user and key in the Credential Report."""
        # Initialize message content
        key_report_contents = []

        # Access the credential report and process it
        for row in self.credentials_report:
            # A row is a unique IAM user
            user_name = row["user"]
            LOG.debug("Processing user: %s", user_name)

            if user_name == "<root_account>":
                LOG.debug("Skipping user: %s", user_name)
                continue

            # Test if user is in an exempted group
            try:
                exempted = utils.is_user_exempted(
                    self.client_iam, user_name, self.event_details.exempt_groups
                )
            except ClientError:
                self.has_errors = True
                continue

            # Get Access Keys for user
            try:
                access_keys = utils.get_user_access_keys(self.client_iam, user_name)
            except ClientError:
                self.has_errors = True
                continue

            for key in access_keys:
                try:
                    key_age = utils.object_age(key["CreateDate"])
                    last_used_date = utils.get_key_last_used_date(
                        self.client_iam, key["AccessKeyId"], user_name
                    )

                    key_report_row = self.process_user_access_key(
                        key, user_name, exempted, key_age, last_used_date
                    )

                    if key_report_row:
                        key_report_contents.append(
                            get_row_details(key_report_row, key_age, last_used_date)
                        )

                except ClientError:
                    self.has_errors = True
                    continue

        return key_report_contents

    def process_user_access_key(
        self, key, user_name, exempted, key_age, last_used_date
    ):
        """Process each access key for a user."""

        access_key_id = key["AccessKeyId"]

        # Log Access Key Details
        LOG.info(
            "User Key Details: %s \t %s \t %s \t %s \t %s",
            user_name,
            access_key_id,
            str(key_age),
            key["Status"],
            str(last_used_date),
        )

        if not exempted and not last_used_date and key_age >= KEY_USE_THRESHOLD:
            # Not Exempted and Key has not been used and
            # is older than the usage threshold, delete and report
            return self.process_delete(access_key_id, user_name, key_age)

        if key_age < KEY_AGE_WARNING:
            # Key age is < warning, do nothing, continue
            return None
        if exempted:
            # EXEMPT:, do not take action on key, but report it
            return IAMKeyReportRow(
                user_name,
                access_key_id,
                EXEMPT_ACTION,
                status=f'{key["Status"]} (Exempt)',
            )

        if key_age >= KEY_AGE_DELETE:
            # NOT EXEMPT: Key is older than the age to delete
            # Attempt to delete and add row to report
            return self.process_delete(access_key_id, user_name, key_age)

        if key_age >= KEY_AGE_INACTIVE:
            # NOT EXEMPT: Key is older than the age to disable
            # Attempt to disable and add row to report
            return self.process_disable(access_key_id, user_name, key_age, key)

        # NOT EXEMPT: If are here the key is old enough to warn about
        # but not old enough to delete or disable, so add a warning to report
        return IAMKeyReportRow(
            user_name, access_key_id, WARN_ACTION, status=key["Status"]
        )

    def process_disable(self, access_key_id, user_name, key_age, key):
        """Call disable on access key and get key status message."""
        status = None
        has_error = False
        try:
            self.disable_access_key(access_key_id, user_name, key_age)
            status = key["Status"]
        except ClientError:
            self.has_errors = True
            status = f'{key["Status"]} (Errror Disabling Key)'
        except IamKeyEnforcerEmailError:
            self.has_errors = True
            status = f'{key["Status"]} (Error Sending User Email)'
        return IAMKeyReportRow(
            user_name, access_key_id, action=DISABLE_ACTION, status=status
        )

    def process_delete(self, access_key_id, user_name, key_age):
        """Call delete on access key and get key status message and error status."""
        status = None
        try:
            self.delete_access_key(access_key_id, user_name, key_age)
        except ClientError:
            self.has_errors = True
            status = "ERROR DELETING"
        except IamKeyEnforcerEmailError:
            self.has_errors = True
            status = "DELETED (Email User Error)"
        return IAMKeyReportRow(
            user_name, access_key_id, action=DELETE_ACTION, status=status
        )

    def disable_access_key(self, access_key_id, user_name, key_age):
        """Disable Access Key."""
        armed_log_prefix = NOT_ARMED_PREFIX
        is_armed = self.armed
        if is_armed:
            armed_log_prefix = ARMED_PREFIX
        LOG.info(
            "%s Disabling AccessKeyId %s for user %s",
            armed_log_prefix,
            access_key_id,
            user_name,
        )

        if is_armed:
            self.client_iam.update_access_key(
                UserName=user_name, AccessKeyId=access_key_id, Status="Inactive"
            )

        if self.event_details.email_user_enabled:
            armed_state_msg = (
                "has been marked 'Inactive'"
                if is_armed
                else "would be marked 'Inactive'"
            )
            self.email_user(
                armed_state_msg, access_key_id, "disabled", key_age, user_name
            )
        else:
            LOG.info(
                "Email User not enabled per event email_user_enabled variable setting"
            )

    def delete_access_key(self, access_key_id, user_name, key_age):
        """Delete Access Key."""
        armed_log_prefix = NOT_ARMED_PREFIX
        is_armed = self.armed
        if is_armed:
            armed_log_prefix = ARMED_PREFIX
        LOG.info(
            "%s Deleting AccessKeyId %s for user %s",
            armed_log_prefix,
            access_key_id,
            user_name,
        )
        if is_armed:
            self.client_iam.delete_access_key(
                UserName=user_name, AccessKeyId=access_key_id
            )

        if self.event_details.email_user_enabled:
            armed_state_msg = (
                "has been deleted" if is_armed else "would be marked for deletion"
            )

            self.email_user(
                armed_state_msg, access_key_id, "deleted", key_age, user_name
            )
        else:
            LOG.info(
                "Email User not enabled per event email_user_enabled variable setting"
            )

    def email_user(self, armed_state_msg, access_key_id, action, key_age, user_name):
        """Email user."""

        to_addresses = self.get_to_addresses_for_user_email(user_name)

        if not to_addresses:
            LOG.error("User email list is empty, no emails sent")
            return

        template_data = self.create_email_template_data(
            armed_state_msg, access_key_id, action, key_age, user_name
        )

        try:
            response = utils.send_email(
                EMAIL_USER_TEMPLATE, template_data, to_addresses
            )
            LOG.info(
                "User Email Sent Successfully. Message ID: %s", response["MessageId"]
            )
        except ClientError as error:
            LOG.exception(
                "Error sending user email - %s", error.response["Error"]["Code"]
            )
            raise IamKeyEnforcerEmailError("Error sending user email") from error

    def get_to_addresses_for_user_email(self, user_name):
        """Get the list of email address to send the user email to."""
        to_addresses = get_to_addresses(self.event_details.email_targets, self.is_debug)
        user_email = self.get_user_email(user_name, self.is_debug)
        if user_email:
            to_addresses.append(user_email)

        return to_addresses

    def create_email_template_data(
        self, armed_state_msg, access_key_id, action, key_age, user_name
    ):
        """Email user."""

        user_key_details = {
            "armed_state_msg": armed_state_msg,
            "access_key_id": access_key_id,
            "action": action,
            "key_age": key_age,
            "user_name": user_name,
        }

        return user_email_template_data(user_key_details, self.event_details.armed)

    def get_user_email(self, user_name, is_debug):
        """Get and validate user email from Key Tags."""
        tags = self.client_iam.list_user_tags(UserName=user_name)
        email = None
        for tag in tags["Tags"]:
            if tag["Key"].lower() == EMAIL_TAG:
                email = tag["Value"]
                break

        if not email:
            LOG.debug("No email found for user %s", user_name)
            return None

        if validate_email(email):
            if not is_debug:
                return email
            LOG.debug("Debug Mode: Append user email %s", email)
        else:
            log_invalid_email(f"user ({user_name})", email)

        return None


def email_admin_report(email_targets, template_data, is_debug):
    """Email admin."""
    if not EMAIL_ADMIN_REPORT_ENABLED:
        LOG.info("Admin Email not enabled per setting")
        return

    to_addresses = get_to_addresses(email_targets, is_debug)

    if not to_addresses:
        LOG.error("Admin email list is empty, no emails sent")
        return

    try:
        # Construct and Send Email
        response = utils.send_email(
            EMAIL_ADMIN_TEMPLATE,
            template_data,
            to_addresses,
        )

        LOG.info("Admin Email Sent Successfully. Message ID: %s", response["MessageId"])
    except ClientError as error:
        LOG.exception("Error sending admin email - %s", error.response["Error"]["Code"])
        raise IamKeyEnforcerEmailError("Error sending admin email") from error


def get_to_addresses(event_email_targets, is_debug):
    """Get the addresses to send the user email to."""
    to_addresses = []

    if validate_email(ADMIN_EMAIL):
        to_addresses.append(ADMIN_EMAIL)
    else:
        log_invalid_email("admin", ADMIN_EMAIL)

    event_email_targets = get_event_email_list(event_email_targets, is_debug)
    to_addresses.extend(event_email_targets)

    return to_addresses


def get_event_email_list(email_targets, is_debug):
    """Get list of email targets from the provided event."""
    email_list = []
    for email_target in email_targets:
        if validate_email(email_target):
            email_list.append(email_target)
        else:
            log_invalid_email("target", email_target)

    # if mode is debug we do not want to email the actual targets
    # log whatever targets there were and return an empty list
    if is_debug and email_list:
        LOG.debug("Debug Mode:Event email targets %s", ", ".join(email_list))
        return []
    return email_list


def log_invalid_email(email_type, email):
    """Log error for invalid email and specify the type."""
    LOG.error("Invalid %s email found - email: %s", email_type, email)


def validate_email(email):
    """Validate email provided matches regex."""
    if not email or not re.fullmatch(EMAIL_REGEX, email):
        return False

    return True


def get_admin_email_template_data(
    key_report_contents, account_number, account_name, armed, exempt_groups
):
    """Build email template data for admin emails."""
    template_data = {
        "account_number": account_number,
        "account_name": account_name,
        "key_report_contents": key_report_contents,
        "key_age_inactive": KEY_AGE_INACTIVE,
        "key_age_delete": KEY_AGE_DELETE,
        "key_age_warning": KEY_AGE_WARNING,
        "key_use_threshold": KEY_USE_THRESHOLD,
    }

    template_data.update(optional_email_template_data(armed, exempt_groups))
    return template_data


def user_email_template_data(user_email_details, armed):
    """Build email template data for user emails."""
    template_data = {
        "armed_state_msg": user_email_details["armed_state_msg"],
        "access_key_id": user_email_details["access_key_id"],
        "action": user_email_details["action"],
        "key_age": user_email_details["key_age"],
        "user_name": user_email_details["user_name"],
    }
    template_data.update(optional_email_template_data(armed))
    return template_data


def optional_email_template_data(armed, exempt_groups=None):
    """Set and return optional email template data."""
    template_data = {}
    if EMAIL_BANNER_MSG:
        template_data["email_banner_msg"] = EMAIL_BANNER_MSG
        template_data["email_banner_msg_color"] = EMAIL_BANNER_MSG_COLOR

    if not armed:
        template_data["unarmed"] = True

    if exempt_groups:
        template_data["exempt_groups"] = exempt_groups

    return template_data


def store_admin_report(account_number, admin_template_data):
    """Store email report in S3 Bucket."""
    if not S3_ENABLED:
        LOG.info("S3 report not enabled per setting")
        return

    try:
        utils.store_in_s3(account_number, admin_template_data)
    except ClientError as error:
        LOG.exception(
            "Error generating/storing report in S3 Bucket %s - error %s",
            S3_BUCKET,
            error.response["Error"]["Code"],
        )
        raise error


def get_row_details(key_report_row, key_age, last_used_date):
    """Get the key enforce report details as a dict."""
    return {
        "bg_color": key_report_row.get_row_bg_color(),
        "user_name": key_report_row.user_name,
        "access_key_id": key_report_row.access_key_id,
        "key_age": str(key_age),
        "key_status": key_report_row.status,
        "last_used_date": str(last_used_date),
    }
