"""Custom Exceptions for IAM Key Enforcer."""


class GenerateCredentialReportThrottleError(Exception):
    """Raised when there is a throttle generating the credential report."""


class IamKeyEnforcerError(Exception):
    """All errors raised by IamKeyEnforcer Lambda."""


class IamKeyEnforcerEmailError(Exception):
    """Raised when there is an SES Client Email Error."""
