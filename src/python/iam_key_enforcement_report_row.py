"""IAM Key Enforcement Row Data"""

# Constants for enforcement actions
DELETE_ACTION = "DELETE"
DISABLE_ACTION = "DISABLE"
EXEMPT_ACTION = "EXEMPT"
WARN_ACTION = "WARNING"

ROW_BG_COLORS = {
    "DELETE": "#E6B0AA",
    "DISABLE": "#F4D03F",
    "EXEMPT": "#D7DBDD",
    "WARNING": "#FFFFFF",
}


class IAMKeyReportRow:
    """Data structure for IAM Key Report Row"""

    def __init__(self, user_name, access_key_id, action, status=None):
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
