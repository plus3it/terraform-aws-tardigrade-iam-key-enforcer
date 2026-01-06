"""Module to handle sending user notification emails for access key actions."""

import json
import re
from constants import (
    ADMIN_EMAIL,
    CLIENT_SES,
    EMAIL_ADMIN_REPORT_ENABLED,
    EMAIL_ADMIN_TEMPLATE,
    EMAIL_BANNER_MSG,
    EMAIL_BANNER_MSG_COLOR,
    EMAIL_REGEX,
    EMAIL_SOURCE,
    LOG,
    EMAIL_USER_TEMPLATE,
    EMAIL_TAG,
)


class AdminMailer:
    """Class to handle sending admin the enforcement report."""

    def __init__(self, email_targets, template_data, is_debug=True):
        """Create Admin Mailer."""
        self.email_targets = email_targets
        self.template_data = template_data
        self.is_debug = is_debug

    def mail(self):
        """Email admin."""
        if not EMAIL_ADMIN_REPORT_ENABLED:
            LOG.info("Admin Email not enabled per setting")
            return

        to_addresses = self.admin_email_addresses()

        if not to_addresses:
            LOG.error("Admin email list is empty, no emails sent")
            return

        # Construct and Send Email
        response = send_email(
            EMAIL_ADMIN_TEMPLATE,
            self.template_data,
            to_addresses,
        )
        LOG.info("Admin Email Sent Successfully. Message ID: %s", response["MessageId"])

    def admin_email_addresses(self):
        """Get All Valid Admin Emails."""
        return get_to_addresses(self.email_targets, self.is_debug)


class UserMailer:
    """Class to handle sending user notification emails for access key actions."""

    def __init__(self, email_targets, user_email, template_data, is_debug=True):
        """Create User Mailer."""
        self.email_targets = email_targets
        self.user_email = user_email
        self.template_data = template_data
        self.is_debug = is_debug

    def mail(self):
        """Email user."""
        to_addresses = self.user_to_addresses()

        if not to_addresses:
            LOG.error("User email list is empty, no emails sent")
            return

        response = send_email(EMAIL_USER_TEMPLATE, self.template_data, to_addresses)
        LOG.info("User Email Sent Successfully. Message ID: %s", response["MessageId"])

    def user_to_addresses(self):
        """Get the list of email address to send the user email to."""
        to_addresses = get_to_addresses(self.email_targets, self.is_debug)
        if self.user_email:
            to_addresses.append(self.user_email)

        return to_addresses


def get_user_email_from_tags(user_name, tags, is_debug):
    """Get and validate user email from Key Tags."""
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
        LOG.debug("Debug Mode: Found user email %s", email)
    else:
        log_invalid_email(f"user ({user_name})", email)

    return None


def log_invalid_email(email_type, email):
    """Log error for invalid email and specify the type."""
    LOG.error("Invalid %s email found - email: %s", email_type, email)


def validate_email(email):
    """Validate email provided matches regex."""
    if not email or not re.fullmatch(EMAIL_REGEX, email):
        return False
    return True


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
