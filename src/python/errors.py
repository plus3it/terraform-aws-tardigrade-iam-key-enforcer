"""Custom Exceptions for IAM Key Enforcer."""


class IamKeyEnforcerError(Exception):
    """Generic IamKeyEnforcer Lambda Error."""


class TemplateDataError(Exception):
    """Error generating the email template from the data provided."""


class GenerateCredentialReportThrottleError(Exception):
    """Raised when there is a throttle generating the credential report."""


class InvalidReportRowError(Exception):
    """Raised when IAM Key Report Row data is invalid."""
