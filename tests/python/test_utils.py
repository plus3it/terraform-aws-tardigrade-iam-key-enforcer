"""
Tests for Utils Module.

This module contains comprehensive unit tests for utility functions
including IAM key operations, S3 storage, user exemptions, and date calculations.

"""

import json
from datetime import UTC, datetime, timedelta

import pytest
from errors import TemplateDataError
from utils import (
    action_armed_state_message,
    get_key_last_used_date,
    get_user_access_keys,
    is_user_exempted,
    object_age,
    root_user,
    store_in_s3,
)


class TestGetKeyLastUsedDate:
    """Tests for get_key_last_used_date function."""

    def test_get_key_last_used_date_with_date(self, mocker):
        """Test getting last used date when key has been used."""
        mock_iam = mocker.MagicMock()
        last_used = datetime.now(tz=UTC)
        mock_iam.get_access_key_last_used.return_value = {
            "AccessKeyLastUsed": {"LastUsedDate": last_used},
        }

        result = get_key_last_used_date(mock_iam, "AKIAIOSFODNN7EXAMPLE")

        assert result == last_used
        mock_iam.get_access_key_last_used.assert_called_once_with(
            AccessKeyId="AKIAIOSFODNN7EXAMPLE",
        )

    def test_get_key_last_used_date_never_used(self, mocker):
        """Test getting last used date when key has never been used."""
        mock_iam = mocker.MagicMock()
        mock_iam.get_access_key_last_used.return_value = {
            "AccessKeyLastUsed": {},
        }

        result = get_key_last_used_date(mock_iam, "AKIAIOSFODNN7EXAMPLE")

        assert result is None
        mock_iam.get_access_key_last_used.assert_called_once_with(
            AccessKeyId="AKIAIOSFODNN7EXAMPLE",
        )

    def test_get_key_last_used_date_different_key(self, mocker):
        """Test getting last used date for different access key."""
        mock_iam = mocker.MagicMock()
        last_used = datetime(2025, 1, 1, 12, 0, 0, tzinfo=UTC)
        mock_iam.get_access_key_last_used.return_value = {
            "AccessKeyLastUsed": {"LastUsedDate": last_used},
        }

        result = get_key_last_used_date(mock_iam, "AKIAI44QH8DHBEXAMPLE")

        assert result == last_used
        mock_iam.get_access_key_last_used.assert_called_once_with(
            AccessKeyId="AKIAI44QH8DHBEXAMPLE",
        )


class TestIsUserExempted:
    """Tests for is_user_exempted function."""

    def test_user_exempted_in_group(self, mocker):
        """Test user is exempted when in exempt group."""
        mock_iam = mocker.MagicMock()
        mock_iam.list_groups_for_user.return_value = {
            "Groups": [
                {"GroupName": "admins"},
                {"GroupName": "developers"},
            ],
        }
        mock_log_info = mocker.patch("utils.LOG.info")
        exempt_groups = ["admins", "operators"]

        result = is_user_exempted(mock_iam, "test-user", exempt_groups)

        assert result is True
        mock_iam.list_groups_for_user.assert_called_once_with(UserName="test-user")
        mock_log_info.assert_called_once_with(
            "User is exempt via group membership in: %s",
            "admins",
        )

    def test_user_not_exempted(self, mocker):
        """Test user is not exempted when not in exempt group."""
        mock_iam = mocker.MagicMock()
        mock_iam.list_groups_for_user.return_value = {
            "Groups": [
                {"GroupName": "developers"},
                {"GroupName": "qa"},
            ],
        }
        exempt_groups = ["admins", "operators"]

        result = is_user_exempted(mock_iam, "test-user", exempt_groups)

        assert result is False
        mock_iam.list_groups_for_user.assert_called_once_with(UserName="test-user")

    def test_user_no_exempt_groups_defined(self, mocker):
        """Test user exemption when no exempt groups are defined."""
        mock_iam = mocker.MagicMock()
        exempt_groups = []

        result = is_user_exempted(mock_iam, "test-user", exempt_groups)

        assert result is False
        mock_iam.list_groups_for_user.assert_not_called()

    def test_user_exempt_groups_none(self, mocker):
        """Test user exemption when exempt groups is None."""
        mock_iam = mocker.MagicMock()
        exempt_groups = None

        result = is_user_exempted(mock_iam, "test-user", exempt_groups)

        assert result is False
        mock_iam.list_groups_for_user.assert_not_called()

    def test_user_in_no_groups(self, mocker):
        """Test user who is not a member of any groups."""
        mock_iam = mocker.MagicMock()
        mock_iam.list_groups_for_user.return_value = {"Groups": []}
        exempt_groups = ["admins"]

        result = is_user_exempted(mock_iam, "test-user", exempt_groups)

        assert result is False
        mock_iam.list_groups_for_user.assert_called_once_with(UserName="test-user")

    def test_user_multiple_exempt_groups(self, mocker):
        """Test user in multiple exempt groups returns on first match."""
        mock_iam = mocker.MagicMock()
        mock_iam.list_groups_for_user.return_value = {
            "Groups": [
                {"GroupName": "admins"},
                {"GroupName": "operators"},
            ],
        }
        mock_log_info = mocker.patch("utils.LOG.info")
        exempt_groups = ["admins", "operators"]

        result = is_user_exempted(mock_iam, "test-user", exempt_groups)

        assert result is True
        # Should return on first match
        assert mock_log_info.call_count == 1


class TestGetUserAccessKeys:
    """Tests for get_user_access_keys function."""

    def test_get_user_access_keys_single_key(self, mocker):
        """Test getting access keys for user with one key."""
        mock_iam = mocker.MagicMock()
        access_keys_data = [
            {
                "UserName": "test-user",
                "AccessKeyId": "AKIAIOSFODNN7EXAMPLE",
                "Status": "Active",
                "CreateDate": datetime(2025, 1, 1, tzinfo=UTC),
            },
        ]
        mock_iam.list_access_keys.return_value = {"AccessKeyMetadata": access_keys_data}

        result = get_user_access_keys(mock_iam, "test-user")

        assert result == access_keys_data
        mock_iam.list_access_keys.assert_called_once_with(UserName="test-user")

    def test_get_user_access_keys_multiple_keys(self, mocker):
        """Test getting access keys for user with multiple keys."""
        mock_iam = mocker.MagicMock()
        access_keys_data = [
            {
                "UserName": "test-user",
                "AccessKeyId": "AKIAIOSFODNN7EXAMPLE",
                "Status": "Active",
                "CreateDate": datetime(2025, 1, 1, tzinfo=UTC),
            },
            {
                "UserName": "test-user",
                "AccessKeyId": "AKIAI44QH8DHBEXAMPLE",
                "Status": "Inactive",
                "CreateDate": datetime(2024, 6, 1, tzinfo=UTC),
            },
        ]
        mock_iam.list_access_keys.return_value = {"AccessKeyMetadata": access_keys_data}

        result = get_user_access_keys(mock_iam, "test-user")

        assert result == access_keys_data
        assert len(result) == 2
        mock_iam.list_access_keys.assert_called_once_with(UserName="test-user")

    def test_get_user_access_keys_no_keys(self, mocker):
        """Test getting access keys for user with no keys."""
        mock_iam = mocker.MagicMock()
        mock_iam.list_access_keys.return_value = {"AccessKeyMetadata": []}

        result = get_user_access_keys(mock_iam, "test-user")

        assert result == []
        mock_iam.list_access_keys.assert_called_once_with(UserName="test-user")


class TestObjectAge:
    """Tests for object_age function."""

    def test_object_age_with_datetime(self):
        """Test calculating age with datetime object."""
        # Use a date that's 13 days ago from now
        last_changed = datetime.now(tz=UTC) - timedelta(days=13)
        result = object_age(last_changed)

        assert result == 13

    def test_object_age_with_string(self):
        """Test calculating age with ISO date string."""
        # Use a date that's 13 days ago
        last_changed_date = datetime.now(tz=UTC) - timedelta(days=13)
        last_changed = last_changed_date.isoformat()
        result = object_age(last_changed)

        assert result == 13

    def test_object_age_zero_days(self):
        """Test calculating age when object is from today."""
        # Use current time (same day)
        last_changed = datetime.now(tz=UTC)
        result = object_age(last_changed)

        assert result == 0

    def test_object_age_many_days(self):
        """Test calculating age for old object."""
        # Use a date that's 365 days ago
        last_changed = datetime.now(tz=UTC) - timedelta(days=365)
        result = object_age(last_changed)

        assert result == 365

    def test_object_age_invalid_type(self):
        """Test calculating age with invalid type returns 0."""
        result = object_age(12345)

        assert result == 0

    def test_object_age_none(self):
        """Test calculating age with None returns 0."""
        result = object_age(None)

        assert result == 0

    def test_object_age_string_various_formats(self):
        """Test calculating age with various date string formats."""
        # Test various date string formats - all 4 days ago
        base_date = datetime.now(tz=UTC) - timedelta(days=4)
        date_formats = [
            base_date.strftime("%Y-%m-%d"),
            base_date.strftime("%Y-%m-%dT%H:%M:%S"),
            base_date.strftime("%Y-%m-%d %H:%M:%S"),
        ]

        for date_str in date_formats:
            result = object_age(date_str)
            assert result == 4


class TestStoreInS3:
    """Tests for store_in_s3 function."""

    def test_store_in_s3_success(self, mocker):
        """Test successfully storing report in S3."""
        mock_aws = mocker.MagicMock()
        mock_aws.ses.test_render_template.return_value = {
            "RenderedTemplate": "<html>Test Report</html>",
        }
        mock_aws.s3.put_object.return_value = {"ETag": "abc123"}
        mocker.patch("utils.AWSClientManager", return_value=mock_aws)
        mocker.patch("utils.EMAIL_ADMIN_TEMPLATE", "AdminTemplate")
        mocker.patch("utils.S3_BUCKET", "test-bucket")
        mock_log_debug = mocker.patch("utils.LOG.debug")

        template_data = {"key": "value"}

        store_in_s3("123456789012", template_data)

        mock_aws.ses.test_render_template.assert_called_once_with(
            TemplateName="AdminTemplate",
            TemplateData=json.dumps(template_data),
        )
        mock_aws.s3.put_object.assert_called_once()
        call_args = mock_aws.s3.put_object.call_args[1]
        assert call_args["Bucket"] == "test-bucket"
        assert "123456789012/access_key_audit_report_" in call_args["Key"]
        assert ".html" in call_args["Key"]
        assert call_args["Body"] == "<html>Test Report</html>"
        mock_log_debug.assert_called_once()

    def test_store_in_s3_no_rendered_template(self, mocker):
        """Test storing in S3 when template rendering fails."""
        mock_aws = mocker.MagicMock()
        mock_aws.ses.test_render_template.return_value = {}
        mocker.patch("utils.AWSClientManager", return_value=mock_aws)
        mocker.patch("utils.EMAIL_ADMIN_TEMPLATE", "AdminTemplate")

        template_data = {"key": "value"}

        with pytest.raises(TemplateDataError) as excinfo:
            store_in_s3("123456789012", template_data)

        assert "Invalid template data for 123456789012" in str(excinfo.value)
        mock_aws.s3.put_object.assert_not_called()

    def test_store_in_s3_empty_rendered_template(self, mocker):
        """Test storing in S3 when rendered template is empty."""
        mock_aws = mocker.MagicMock()
        mock_aws.ses.test_render_template.return_value = {"RenderedTemplate": ""}
        mocker.patch("utils.AWSClientManager", return_value=mock_aws)
        mocker.patch("utils.EMAIL_ADMIN_TEMPLATE", "AdminTemplate")

        template_data = {"key": "value"}

        with pytest.raises(TemplateDataError) as excinfo:
            store_in_s3("123456789012", template_data)

        assert "Invalid template data for 123456789012" in str(excinfo.value)
        mock_aws.s3.put_object.assert_not_called()

    def test_store_in_s3_different_account(self, mocker):
        """Test storing report for different account number."""
        mock_aws = mocker.MagicMock()
        mock_aws.ses.test_render_template.return_value = {
            "RenderedTemplate": "<html>Report</html>",
        }
        mock_aws.s3.put_object.return_value = {"ETag": "xyz789"}
        mocker.patch("utils.AWSClientManager", return_value=mock_aws)
        mocker.patch("utils.EMAIL_ADMIN_TEMPLATE", "AdminTemplate")
        mocker.patch("utils.S3_BUCKET", "test-bucket")
        mocker.patch("utils.LOG.debug")

        template_data = {"users": []}

        store_in_s3("999888777666", template_data)

        call_args = mock_aws.s3.put_object.call_args[1]
        assert "999888777666/access_key_audit_report_" in call_args["Key"]
        assert ".html" in call_args["Key"]


class TestRootUser:
    """Tests for root_user function."""

    def test_root_user_is_root(self, mocker):
        """Test identifying root account user."""
        mock_log_debug = mocker.patch("utils.LOG.debug")

        result = root_user("<root_account>")

        assert result is True
        mock_log_debug.assert_called_once_with(
            "Skipping root account user: %s",
            "<root_account>",
        )

    def test_root_user_not_root(self, mocker):
        """Test identifying non-root user."""
        mocker.patch("utils.LOG.debug")

        result = root_user("test-user")

        assert result is False

    def test_root_user_empty_string(self, mocker):
        """Test with empty string."""
        mocker.patch("utils.LOG.debug")

        result = root_user("")

        assert result is False

    def test_root_user_similar_name(self, mocker):
        """Test user with similar but not exact root name."""
        mocker.patch("utils.LOG.debug")

        result = root_user("root_account")

        assert result is False

    def test_root_user_case_sensitive(self, mocker):
        """Test that root user check is case sensitive."""
        mocker.patch("utils.LOG.debug")

        result = root_user("<ROOT_ACCOUNT>")

        assert result is False


class TestActionArmedStateMessage:
    """Tests for action_armed_state_message function."""

    def test_delete_action_armed(self, mocker):
        """Test delete action when armed."""
        mocker.patch("utils.DELETE_ACTION", "Delete")

        result = action_armed_state_message("Delete", is_armed=True)

        assert result == "has been deleted"

    def test_delete_action_not_armed(self, mocker):
        """Test delete action when not armed."""
        mocker.patch("utils.DELETE_ACTION", "Delete")

        result = action_armed_state_message("Delete", is_armed=False)

        assert result == "would be marked for deletion"

    def test_disable_action_armed(self, mocker):
        """Test disable action when armed."""
        mocker.patch("utils.DISABLE_ACTION", "Disable")

        result = action_armed_state_message("Disable", is_armed=True)

        assert result == "has been marked 'Inactive'"

    def test_disable_action_not_armed(self, mocker):
        """Test disable action when not armed."""
        mocker.patch("utils.DISABLE_ACTION", "Disable")

        result = action_armed_state_message("Disable", is_armed=False)

        assert result == "would be marked 'Inactive'"

    def test_other_action_returns_none(self, mocker):
        """Test other actions return None."""
        mocker.patch("utils.DELETE_ACTION", "Delete")
        mocker.patch("utils.DISABLE_ACTION", "Disable")

        result = action_armed_state_message("Warning", is_armed=True)

        assert result is None

    def test_exempt_action_returns_none(self, mocker):
        """Test exempt action returns None."""
        mocker.patch("utils.DELETE_ACTION", "Delete")
        mocker.patch("utils.DISABLE_ACTION", "Disable")

        result = action_armed_state_message("Exempt", is_armed=False)

        assert result is None

    def test_empty_action_returns_none(self, mocker):
        """Test empty action string returns None."""
        mocker.patch("utils.DELETE_ACTION", "Delete")
        mocker.patch("utils.DISABLE_ACTION", "Disable")

        result = action_armed_state_message("", is_armed=True)

        assert result is None
