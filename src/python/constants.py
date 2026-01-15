"""Constants that are used across the project."""

import os
import re
import sys

from aws_lambda_powertools import Logger

# Standard logging config
LOG_LEVEL = os.environ.get("LOG_LEVEL", "info")
LOG = Logger(
    service="iam_key_enforcer",
    level=LOG_LEVEL,
    stream=sys.stderr,
    location="%(name)s.%(funcName)s:%(lineno)d",
    timestamp="%(asctime)s.%(msecs)03dZ",
    datefmt="%Y-%m-%dT%H:%M:%S",
)


# Key Enforcer Thresholds (in days)
KEY_AGE_WARNING = int(os.environ.get("KEY_AGE_WARNING", 75))
KEY_AGE_INACTIVE = int(os.environ.get("KEY_AGE_INACTIVE", 90))
KEY_AGE_DELETE = int(os.environ.get("KEY_AGE_DELETE", 120))
KEY_USE_THRESHOLD = int(os.environ.get("KEY_USE_THRESHOLD", 30))

# Email Addresses
EMAIL_SOURCE = os.environ.get("EMAIL_SOURCE")
EMAIL_TAG = os.environ.get("EMAIL_TAG", "keyenforcer:email").lower()

# Admin Email to send admin reports to
ADMIN_EMAIL = os.environ.get("ADMIN_EMAIL")
EMAIL_ADMIN_REPORT_ENABLED = (
    os.environ.get("EMAIL_ADMIN_REPORT_ENABLED", "False").lower() == "true"
)

# S3 Details to store admin report in
S3_ENABLED = os.environ.get("S3_ENABLED", "False").lower() == "true"
S3_BUCKET = os.environ.get("S3_BUCKET", None)

# Email Template Details
EMAIL_BANNER_MSG = os.environ.get("EMAIL_BANNER_MSG", "").strip()
EMAIL_BANNER_MSG_COLOR = os.environ.get("EMAIL_BANNER_MSG_COLOR", "black").strip()
EMAIL_USER_TEMPLATE = os.environ.get("EMAIL_USER_TEMPLATE")
EMAIL_ADMIN_TEMPLATE = os.environ.get("EMAIL_ADMIN_TEMPLATE")

# Prefixes for messages based on whether the enforemcent is armed or not
NOT_ARMED_PREFIX = "NOT ARMED:"
ARMED_PREFIX = "ARMED:"

# When errors occur, we log them, set a flag that the run had errors
# and continue processing. At the end of processing all users and keys
# if the run had errors we raise an error with this message
DEFAULT_PROCESSING_ERROR_MSG = "Errors occurred during processing, see logs"

# Regex to validate that the email set in a tag is valid
EMAIL_REGEX = re.compile(
    r"([A-Za-z0-9]+[._-])*[A-Za-z0-9]+@[A-Za-z0-9-]+(\.[A-Z|a-z]{2,})+",
)

# Actions to take on keys
# Constants for enforcement actions
DELETE_ACTION = "Delete"
DISABLE_ACTION = "Disable"
EXEMPT_ACTION = "Exempt"
WARN_ACTION = "Warning"
NO_ACTION = "None"
UNUSED_ACTION = "Unused"

ACTION_REASONS = {
    DELETE_ACTION: f"key age is >= delete age ({KEY_AGE_DELETE} days) ",
    DISABLE_ACTION: f"key must be rotated at {KEY_AGE_INACTIVE} days",
    EXEMPT_ACTION: "user in exempted group",
    WARN_ACTION: f"key age is >= warning age ({KEY_AGE_WARNING} days)",
    NO_ACTION: f"key age < warning age ({KEY_AGE_WARNING} days)",
    UNUSED_ACTION: f"key was NOT USED before {KEY_USE_THRESHOLD} days",
}
