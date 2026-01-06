"""Constants that are used across the project."""

import os
import re
import sys
import boto3
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

# Get the Lambda session and clients
SESSION = boto3.Session()
CLIENT_SES = SESSION.client("ses")
CLIENT_S3 = SESSION.client("s3")

# Environment Variables
ADMIN_EMAIL = os.environ.get("ADMIN_EMAIL")
EMAIL_ADMIN_REPORT_ENABLED = (
    os.environ.get("EMAIL_ADMIN_REPORT_ENABLED", "False").lower() == "true"
)

KEY_AGE_WARNING = int(os.environ.get("KEY_AGE_WARNING", 75))
KEY_AGE_INACTIVE = int(os.environ.get("KEY_AGE_INACTIVE", 90))
KEY_AGE_DELETE = int(os.environ.get("KEY_AGE_DELETE", 120))
KEY_USE_THRESHOLD = int(os.environ.get("KEY_USE_THRESHOLD", 30))
S3_ENABLED = os.environ.get("S3_ENABLED", "False").lower() == "true"
S3_BUCKET = os.environ.get("S3_BUCKET", None)
EMAIL_TAG = os.environ.get("EMAIL_TAG", "keyenforcer:email").lower()
EMAIL_BANNER_MSG = os.environ.get("EMAIL_BANNER_MSG", "").strip()
EMAIL_BANNER_MSG_COLOR = os.environ.get("EMAIL_BANNER_MSG_COLOR", "black").strip()
EMAIL_USER_TEMPLATE = os.environ.get("EMAIL_USER_TEMPLATE")
EMAIL_ADMIN_TEMPLATE = os.environ.get("EMAIL_ADMIN_TEMPLATE")
NOT_ARMED_PREFIX = "NOT ARMED:"
ARMED_PREFIX = "ARMED:"
DEFAULT_PROCESSING_ERROR_MSG = "Errors occurred during processing, see logs"

EMAIL_REGEX = re.compile(
    r"([A-Za-z0-9]+[._-])*[A-Za-z0-9]+@[A-Za-z0-9-]+(\.[A-Z|a-z]{2,})+"
)
