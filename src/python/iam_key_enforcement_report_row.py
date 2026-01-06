"""IAM Key Enforcement Row Data."""

from constants import DELETE_ACTION, DISABLE_ACTION, EXEMPT_ACTION, WARN_ACTION

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
        """Create IAMKeyReportRow."""
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
