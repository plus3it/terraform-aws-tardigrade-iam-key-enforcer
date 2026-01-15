"""
Tests for IAM Key Enforcement Report Row.

This module contains comprehensive unit tests for the IAMKeyReportRow class,
including validation, data conversion, and background color assignment.

"""

import pytest
from constants import (
    DELETE_ACTION,
    DISABLE_ACTION,
    EXEMPT_ACTION,
    NO_ACTION,
    UNUSED_ACTION,
    WARN_ACTION,
)
from errors import InvalidReportRowError
from iam_key_enforcement_report_row import VALID_ACTIONS, IAMKeyReportRow


class TestIAMKeyReportRowCreation:
    """Tests for IAMKeyReportRow creation and validation."""

    def test_create_with_valid_delete_action(self):
        """Test creating IAMKeyReportRow with DELETE_ACTION."""
        row = IAMKeyReportRow("test-user", "AKIAIOSFODNN7EXAMPLE", DELETE_ACTION)

        assert row.user_name == "test-user"
        assert row.access_key_id == "AKIAIOSFODNN7EXAMPLE"
        assert row.action == DELETE_ACTION
        assert row.status is None

    def test_create_with_valid_disable_action(self):
        """Test creating IAMKeyReportRow with DISABLE_ACTION."""
        row = IAMKeyReportRow(
            "test-user",
            "AKIAIOSFODNN7EXAMPLE",
            DISABLE_ACTION,
            "Active",
        )

        assert row.user_name == "test-user"
        assert row.access_key_id == "AKIAIOSFODNN7EXAMPLE"
        assert row.action == DISABLE_ACTION
        assert row.status == "Active"

    def test_create_with_valid_exempt_action(self):
        """Test creating IAMKeyReportRow with EXEMPT_ACTION."""
        row = IAMKeyReportRow("test-user", "AKIAIOSFODNN7EXAMPLE", EXEMPT_ACTION)

        assert row.user_name == "test-user"
        assert row.action == EXEMPT_ACTION

    def test_create_with_valid_warn_action(self):
        """Test creating IAMKeyReportRow with WARN_ACTION."""
        row = IAMKeyReportRow("test-user", "AKIAIOSFODNN7EXAMPLE", WARN_ACTION)

        assert row.action == WARN_ACTION

    def test_create_with_valid_no_action(self):
        """Test creating IAMKeyReportRow with NO_ACTION."""
        row = IAMKeyReportRow("test-user", "AKIAIOSFODNN7EXAMPLE", NO_ACTION)

        assert row.action == NO_ACTION

    def test_create_with_valid_unused_action(self):
        """Test creating IAMKeyReportRow with UNUSED_ACTION."""
        row = IAMKeyReportRow("test-user", "AKIAIOSFODNN7EXAMPLE", UNUSED_ACTION)

        assert row.action == UNUSED_ACTION

    def test_create_with_all_parameters(self):
        """Test creating IAMKeyReportRow with all parameters including status."""
        row = IAMKeyReportRow(
            "admin-user",
            "AKIAIOSFODNN7EXAMPLE",
            DELETE_ACTION,
            "Inactive",
        )

        assert row.user_name == "admin-user"
        assert row.access_key_id == "AKIAIOSFODNN7EXAMPLE"
        assert row.action == DELETE_ACTION
        assert row.status == "Inactive"


class TestIAMKeyReportRowValidation:
    """Tests for IAMKeyReportRow input validation."""

    def test_empty_user_name_raises_error(self):
        """Test that empty user_name raises InvalidReportRowError."""
        with pytest.raises(InvalidReportRowError, match="user_name cannot be empty"):
            IAMKeyReportRow("", "AKIAIOSFODNN7EXAMPLE", DELETE_ACTION)

    def test_none_user_name_raises_error(self):
        """Test that None user_name raises InvalidReportRowError."""
        with pytest.raises(InvalidReportRowError, match="user_name cannot be empty"):
            IAMKeyReportRow(None, "AKIAIOSFODNN7EXAMPLE", DELETE_ACTION)

    def test_whitespace_user_name_raises_error(self):
        """Test that whitespace-only user_name raises InvalidReportRowError."""
        with pytest.raises(InvalidReportRowError, match="user_name cannot be empty"):
            IAMKeyReportRow("   ", "AKIAIOSFODNN7EXAMPLE", DELETE_ACTION)

    def test_non_string_user_name_raises_error(self):
        """Test that non-string user_name raises InvalidReportRowError."""
        with pytest.raises(InvalidReportRowError, match="user_name cannot be empty"):
            IAMKeyReportRow(123, "AKIAIOSFODNN7EXAMPLE", DELETE_ACTION)

    def test_empty_access_key_id_raises_error(self):
        """Test that empty access_key_id raises InvalidReportRowError."""
        with pytest.raises(
            InvalidReportRowError,
            match="access_key_id cannot be empty",
        ):
            IAMKeyReportRow("test-user", "", DELETE_ACTION)

    def test_none_access_key_id_raises_error(self):
        """Test that None access_key_id raises InvalidReportRowError."""
        with pytest.raises(
            InvalidReportRowError,
            match="access_key_id cannot be empty",
        ):
            IAMKeyReportRow("test-user", None, DELETE_ACTION)

    def test_whitespace_access_key_id_raises_error(self):
        """Test that whitespace-only access_key_id raises InvalidReportRowError."""
        with pytest.raises(
            InvalidReportRowError,
            match="access_key_id cannot be empty",
        ):
            IAMKeyReportRow("test-user", "   ", DELETE_ACTION)

    def test_non_string_access_key_id_raises_error(self):
        """Test that non-string access_key_id raises InvalidReportRowError."""
        with pytest.raises(
            InvalidReportRowError,
            match="access_key_id cannot be empty",
        ):
            IAMKeyReportRow("test-user", 456, DELETE_ACTION)

    def test_invalid_action_raises_error(self):
        """Test that invalid action raises InvalidReportRowError."""
        with pytest.raises(InvalidReportRowError, match="Invalid action"):
            IAMKeyReportRow("test-user", "AKIAIOSFODNN7EXAMPLE", "InvalidAction")

    def test_invalid_action_shows_valid_options(self):
        """Test that error message includes valid action options."""
        with pytest.raises(InvalidReportRowError, match="Must be one of:"):
            IAMKeyReportRow("test-user", "AKIAIOSFODNN7EXAMPLE", "BadAction")

    def test_empty_action_raises_error(self):
        """Test that empty action raises InvalidReportRowError."""
        with pytest.raises(InvalidReportRowError, match="Invalid action"):
            IAMKeyReportRow("test-user", "AKIAIOSFODNN7EXAMPLE", "")

    def test_none_action_raises_error(self):
        """Test that None action raises InvalidReportRowError."""
        with pytest.raises(InvalidReportRowError, match="Invalid action"):
            IAMKeyReportRow("test-user", "AKIAIOSFODNN7EXAMPLE", None)


class TestIAMKeyReportRowMethods:
    """Tests for IAMKeyReportRow methods."""

    def test_to_dict_with_status(self):
        """Test to_dict method returns correct dictionary with status."""
        row = IAMKeyReportRow(
            "test-user",
            "AKIAIOSFODNN7EXAMPLE",
            DELETE_ACTION,
            "Active",
        )

        result = row.to_dict()

        assert result == {
            "user_name": "test-user",
            "access_key_id": "AKIAIOSFODNN7EXAMPLE",
            "action": DELETE_ACTION,
            "status": "Active",
        }

    def test_to_dict_without_status(self):
        """Test to_dict method returns correct dictionary without status."""
        row = IAMKeyReportRow("test-user", "AKIAIOSFODNN7EXAMPLE", WARN_ACTION)

        result = row.to_dict()

        assert result == {
            "user_name": "test-user",
            "access_key_id": "AKIAIOSFODNN7EXAMPLE",
            "action": WARN_ACTION,
            "status": None,
        }

    def test_get_row_bg_color_delete_action(self):
        """Test get_row_bg_color returns correct color for DELETE_ACTION."""
        row = IAMKeyReportRow("test-user", "AKIAIOSFODNN7EXAMPLE", DELETE_ACTION)

        color = row.get_row_bg_color()

        assert color == "#E6B0AA"

    def test_get_row_bg_color_disable_action(self):
        """Test get_row_bg_color returns correct color for DISABLE_ACTION."""
        row = IAMKeyReportRow("test-user", "AKIAIOSFODNN7EXAMPLE", DISABLE_ACTION)

        color = row.get_row_bg_color()

        assert color == "#F4D03F"

    def test_get_row_bg_color_exempt_action(self):
        """Test get_row_bg_color returns correct color for EXEMPT_ACTION."""
        row = IAMKeyReportRow("test-user", "AKIAIOSFODNN7EXAMPLE", EXEMPT_ACTION)

        color = row.get_row_bg_color()

        assert color == "#D7DBDD"

    def test_get_row_bg_color_warn_action(self):
        """Test get_row_bg_color returns correct color for WARN_ACTION."""
        row = IAMKeyReportRow("test-user", "AKIAIOSFODNN7EXAMPLE", WARN_ACTION)

        color = row.get_row_bg_color()

        assert color == "#FFFFFF"

    def test_get_row_bg_color_no_action_default(self):
        """Test get_row_bg_color returns default color for NO_ACTION."""
        row = IAMKeyReportRow("test-user", "AKIAIOSFODNN7EXAMPLE", NO_ACTION)

        color = row.get_row_bg_color()

        # NO_ACTION is not in ROW_BG_COLORS, should return default
        assert color == "#FFFFFF"

    def test_get_row_bg_color_unused_action_default(self):
        """Test get_row_bg_color returns default color for UNUSED_ACTION."""
        row = IAMKeyReportRow("test-user", "AKIAIOSFODNN7EXAMPLE", UNUSED_ACTION)

        color = row.get_row_bg_color()

        # UNUSED_ACTION is not in ROW_BG_COLORS, should return default
        assert color == "#FFFFFF"


class TestValidActionsConstant:
    """Tests for the VALID_ACTIONS constant."""

    def test_valid_actions_contains_all_expected_actions(self):
        """Test that VALID_ACTIONS contains all expected action values."""
        expected_actions = {
            DELETE_ACTION,
            DISABLE_ACTION,
            EXEMPT_ACTION,
            WARN_ACTION,
            NO_ACTION,
            UNUSED_ACTION,
        }

        assert expected_actions == VALID_ACTIONS

    def test_valid_actions_is_set(self):
        """Test that VALID_ACTIONS is a set for efficient lookup."""
        assert isinstance(VALID_ACTIONS, set)


class TestIAMKeyReportRowEdgeCases:
    """Tests for edge cases and special scenarios."""

    def test_user_name_with_special_characters(self):
        """Test that user_name with special characters is accepted."""
        row = IAMKeyReportRow(
            "test-user@example.com",
            "AKIAIOSFODNN7EXAMPLE",
            DELETE_ACTION,
        )

        assert row.user_name == "test-user@example.com"

    def test_user_name_with_leading_trailing_spaces(self):
        """Test that user_name with leading/trailing spaces is accepted."""
        row = IAMKeyReportRow(
            " test-user ",
            "AKIAIOSFODNN7EXAMPLE",
            DELETE_ACTION,
        )

        # Spaces are preserved, not stripped
        assert row.user_name == " test-user "

    def test_access_key_id_with_different_format(self):
        """Test that various access_key_id formats are accepted."""
        row = IAMKeyReportRow("test-user", "AKIA1234567890ABCDEF", DELETE_ACTION)

        assert row.access_key_id == "AKIA1234567890ABCDEF"

    def test_status_can_be_any_string(self):
        """Test that status accepts any string value."""
        row = IAMKeyReportRow(
            "test-user",
            "AKIAIOSFODNN7EXAMPLE",
            DELETE_ACTION,
            "CustomStatus",
        )

        assert row.status == "CustomStatus"

    def test_multiple_instances_are_independent(self):
        """Test that multiple IAMKeyReportRow instances are independent."""
        row1 = IAMKeyReportRow("user1", "KEY1", DELETE_ACTION, "Active")
        row2 = IAMKeyReportRow("user2", "KEY2", WARN_ACTION, "Inactive")

        assert row1.user_name != row2.user_name
        assert row1.access_key_id != row2.access_key_id
        assert row1.action != row2.action
        assert row1.status != row2.status
