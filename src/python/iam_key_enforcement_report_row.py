"""IAM Key Enforcement Row Data."""

from constants import (
    DELETE_ACTION,
    DISABLE_ACTION,
    EXEMPT_ACTION,
    NO_ACTION,
    UNUSED_ACTION,
    WARN_ACTION,
)
from errors import InvalidReportRowError

# Valid actions for IAM key enforcement
VALID_ACTIONS = {
    DELETE_ACTION,
    DISABLE_ACTION,
    EXEMPT_ACTION,
    WARN_ACTION,
    NO_ACTION,
    UNUSED_ACTION,
}

# Background colors for different actions in the report
ROW_BG_COLORS = {
    DELETE_ACTION: "#E6B0AA",
    DISABLE_ACTION: "#F4D03F",
    EXEMPT_ACTION: "#D7DBDD",
    WARN_ACTION: "#FFFFFF",
}


class IAMKeyReportRow:
    """Data structure for IAM Key Report Row."""

    def __init__(self, user_name, access_key_id, action, status=None):
        """
        Create IAMKeyReportRow.

        Parameters
        ----------
        user_name : str
            The IAM user name (cannot be empty).
        access_key_id : str
            The access key ID (cannot be empty).
        action : str
            The enforcement action (must be a valid action).
        status : str, optional
            The current status of the access key.

        Raises
        ------
        InvalidReportRowError
            If user_name or access_key_id is empty, or action is invalid.

        """
        # Validate user_name is not empty
        if not user_name or not isinstance(user_name, str) or not user_name.strip():
            msg = "user_name cannot be empty"
            raise InvalidReportRowError(msg)

        # Validate access_key_id is not empty
        if (
            not access_key_id
            or not isinstance(access_key_id, str)
            or not access_key_id.strip()
        ):
            msg = "access_key_id cannot be empty"
            raise InvalidReportRowError(msg)

        # Validate action is valid
        if action not in VALID_ACTIONS:
            msg = (
                f"Invalid action '{action}'. "
                f"Must be one of: {', '.join(sorted(VALID_ACTIONS))}"
            )
            raise InvalidReportRowError(msg)

        self.user_name = user_name
        self.access_key_id = access_key_id
        self.action = action
        self.status = status

    def to_dict(self):
        """Convert the report row to a dictionary."""
        return {
            "user_name": self.user_name,
            "access_key_id": self.access_key_id,
            "action": self.action,
            "status": self.status,
        }

    def get_row_bg_color(self):
        """Get the background color for the row based on action."""
        return ROW_BG_COLORS.get(self.action, "#FFFFFF")
