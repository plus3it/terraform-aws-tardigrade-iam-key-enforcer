"""
Tests for IAM Key Enforcer Reporter.

This module contains comprehensive unit tests for the IamKeyEnforcerReporter class
and related functions, including enforcement logic, reporting, and notification.

"""

from datetime import UTC, datetime, timedelta

import pytest
from botocore.exceptions import ClientError
from constants import (
    DELETE_ACTION,
    DISABLE_ACTION,
    EXEMPT_ACTION,
    NO_ACTION,
    WARN_ACTION,
)
from errors import IamKeyEnforcerError
from iam_key_enforcement_report_row import IAMKeyReportRow
from iam_key_enforcer_reporter import (
    IaMAccessKey,
    IaMAccessKeyUser,
    IamKeyEnforcerReporter,
    exempt_groups_string,
    get_enforcement_action,
    log_action,
    report_row_details,
)


class TestIaMAccessKey:
    """Tests for IaMAccessKey dataclass."""

    def test_create_access_key_with_last_used_date(self):
        """Test creating IaMAccessKey with last_used_date."""
        last_used = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)
        boto_key = {"AccessKeyId": "AKIA123", "Status": "Active"}

        key = IaMAccessKey(
            id="AKIA123",
            age=30,
            last_used_date=last_used,
            boto_key=boto_key,
        )

        assert key.id == "AKIA123"
        assert key.age == 30
        assert key.last_used_date == last_used
        assert key.boto_key == boto_key

    def test_create_access_key_without_last_used_date(self):
        """Test creating IaMAccessKey without last_used_date."""
        boto_key = {"AccessKeyId": "AKIA456", "Status": "Inactive"}

        key = IaMAccessKey(
            id="AKIA456",
            age=100,
            last_used_date=None,
            boto_key=boto_key,
        )

        assert key.id == "AKIA456"
        assert key.age == 100
        assert key.last_used_date is None
        assert key.boto_key["Status"] == "Inactive"


class TestIaMAccessKeyUser:
    """Tests for IaMAccessKeyUser dataclass."""

    def test_create_exempted_user(self):
        """Test creating exempted user with access key."""
        boto_key = {"AccessKeyId": "AKIA789", "Status": "Active"}
        key = IaMAccessKey("AKIA789", 50, None, boto_key)

        user = IaMAccessKeyUser(name="test-user", exempted=True, key=key)

        assert user.name == "test-user"
        assert user.exempted is True
        assert user.key == key

    def test_create_non_exempted_user(self):
        """Test creating non-exempted user with access key."""
        boto_key = {"AccessKeyId": "AKIA999", "Status": "Active"}
        key = IaMAccessKey("AKIA999", 90, datetime.now(tz=UTC), boto_key)

        user = IaMAccessKeyUser(name="admin-user", exempted=False, key=key)

        assert user.name == "admin-user"
        assert user.exempted is False
        assert user.key.id == "AKIA999"


class TestIamKeyEnforcerReporterInit:
    """Tests for IamKeyEnforcerReporter initialization."""

    def test_init_with_armed_true(self, mock_iam_client):
        """Test initialization when armed is True."""
        event = {
            "armed": True,
            "account_name": "test-account",
            "account_number": "123456789012",
        }

        reporter = IamKeyEnforcerReporter(mock_iam_client, event)

        assert reporter.client_iam == mock_iam_client
        assert reporter.enforce_details == event
        assert reporter.has_errors is False
        assert reporter.log_prefix == "ARMED:"

    def test_init_with_armed_false(self, mock_iam_client):
        """Test initialization when armed is False."""
        event = {
            "armed": False,
            "account_name": "test-account",
            "account_number": "123456789012",
        }

        reporter = IamKeyEnforcerReporter(mock_iam_client, event)

        assert reporter.client_iam == mock_iam_client
        assert reporter.has_errors is False
        assert reporter.log_prefix == "NOT ARMED:"


class TestReportRowDetails:
    """Tests for report_row_details function."""

    def test_report_row_details_with_all_values(self):
        """Test report_row_details with all values populated."""
        row = IAMKeyReportRow("test-user", "AKIA123", DELETE_ACTION, "Active")
        key_age = 95
        last_used_date = datetime(2025, 12, 1, tzinfo=UTC)

        result = report_row_details(row, key_age, last_used_date)

        assert result["user_name"] == "test-user"
        assert result["access_key_id"] == "AKIA123"
        assert result["key_age"] == "95"
        assert result["key_status"] == "Active"
        assert result["last_used_date"] == str(last_used_date)
        assert "bg_color" in result

    def test_report_row_details_with_none_last_used(self):
        """Test report_row_details with None last_used_date."""
        row = IAMKeyReportRow("admin", "AKIA456", WARN_ACTION, "Inactive")
        key_age = 80
        last_used_date = None

        result = report_row_details(row, key_age, last_used_date)

        assert result["last_used_date"] == "None"
        assert result["key_age"] == "80"


class TestExemptGroupsString:
    """Tests for exempt_groups_string function."""

    def test_with_multiple_groups(self):
        """Test exempt_groups_string with multiple groups."""
        groups = ["admins", "developers", "operators"]

        result = exempt_groups_string(groups)

        assert result == "admins, developers, operators"

    def test_with_single_group(self):
        """Test exempt_groups_string with single group."""
        groups = ["admins"]

        result = exempt_groups_string(groups)

        assert result == "admins"

    def test_with_empty_list(self):
        """Test exempt_groups_string with empty list."""
        groups = []

        result = exempt_groups_string(groups)

        assert result is None

    def test_with_none(self):
        """Test exempt_groups_string with None."""
        result = exempt_groups_string(None)

        assert result is None


class TestGetEnforcementAction:
    """Tests for get_enforcement_action function."""

    def test_unused_key_action(self, mocker):
        """Test action for unused key beyond threshold."""
        boto_key = {"AccessKeyId": "AKIA123", "Status": "Active"}
        key = IaMAccessKey("AKIA123", 40, None, boto_key)
        user = IaMAccessKeyUser("test-user", False, key)

        # Mock the KEY_USE_THRESHOLD to be 30
        mocker.patch("iam_key_enforcer_reporter.KEY_USE_THRESHOLD", 30)

        action = get_enforcement_action(user, "TEST:")

        assert action == DELETE_ACTION

    def test_no_action_for_young_key(self, mocker):
        """Test no action for key younger than warning age."""
        boto_key = {"AccessKeyId": "AKIA123", "Status": "Active"}
        key = IaMAccessKey("AKIA123", 50, datetime.now(tz=UTC), boto_key)
        user = IaMAccessKeyUser("test-user", False, key)

        mocker.patch("iam_key_enforcer_reporter.KEY_AGE_WARNING", 75)

        action = get_enforcement_action(user, "TEST:")

        assert action == NO_ACTION

    def test_exempt_action_for_exempted_user(self, mocker):
        """Test exempt action for exempted user."""
        boto_key = {"AccessKeyId": "AKIA123", "Status": "Active"}
        key = IaMAccessKey("AKIA123", 100, datetime.now(tz=UTC), boto_key)
        user = IaMAccessKeyUser("admin-user", True, key)

        mocker.patch("iam_key_enforcer_reporter.KEY_AGE_WARNING", 75)

        action = get_enforcement_action(user, "TEST:")

        assert action == EXEMPT_ACTION

    def test_delete_action_for_old_key(self, mocker):
        """Test delete action for key older than delete age."""
        boto_key = {"AccessKeyId": "AKIA123", "Status": "Active"}
        key = IaMAccessKey("AKIA123", 130, datetime.now(tz=UTC), boto_key)
        user = IaMAccessKeyUser("test-user", False, key)

        mocker.patch("iam_key_enforcer_reporter.KEY_AGE_DELETE", 120)
        mocker.patch("iam_key_enforcer_reporter.KEY_AGE_WARNING", 75)

        action = get_enforcement_action(user, "TEST:")

        assert action == DELETE_ACTION

    def test_disable_action_for_inactive_age_key(self, mocker):
        """Test disable action for key at inactive age."""
        boto_key = {"AccessKeyId": "AKIA123", "Status": "Active"}
        key = IaMAccessKey("AKIA123", 95, datetime.now(tz=UTC), boto_key)
        user = IaMAccessKeyUser("test-user", False, key)

        mocker.patch("iam_key_enforcer_reporter.KEY_AGE_DELETE", 120)
        mocker.patch("iam_key_enforcer_reporter.KEY_AGE_INACTIVE", 90)
        mocker.patch("iam_key_enforcer_reporter.KEY_AGE_WARNING", 75)

        action = get_enforcement_action(user, "TEST:")

        assert action == DISABLE_ACTION

    def test_warn_action_for_warning_age_key(self, mocker):
        """Test warn action for key at warning age."""
        boto_key = {"AccessKeyId": "AKIA123", "Status": "Active"}
        key = IaMAccessKey("AKIA123", 80, datetime.now(tz=UTC), boto_key)
        user = IaMAccessKeyUser("test-user", False, key)

        mocker.patch("iam_key_enforcer_reporter.KEY_AGE_DELETE", 120)
        mocker.patch("iam_key_enforcer_reporter.KEY_AGE_INACTIVE", 90)
        mocker.patch("iam_key_enforcer_reporter.KEY_AGE_WARNING", 75)

        action = get_enforcement_action(user, "TEST:")

        assert action == WARN_ACTION


class TestLogAction:  # pylint: disable=too-few-public-methods
    """Tests for log_action function."""

    def test_log_action_called_with_correct_parameters(self, mocker):
        """Test that log_action logs with correct parameters."""
        mock_log_info = mocker.patch("iam_key_enforcer_reporter.LOG.info")
        boto_key = {"AccessKeyId": "AKIA123", "Status": "Active"}
        key = IaMAccessKey("AKIA123", 95, None, boto_key)
        user = IaMAccessKeyUser("test-user", False, key)

        log_action(DELETE_ACTION, "key is old", user, "ARMED:")

        mock_log_info.assert_called_once()
        call_args = mock_log_info.call_args[0]
        assert "ARMED:" in call_args
        assert DELETE_ACTION in call_args
        assert "AKIA123" in call_args
        assert "test-user" in call_args


class TestEnforceAction:
    """Tests for enforce_action method."""

    def test_enforce_delete_action_when_armed(self, mock_iam_client):
        """Test delete action enforcement when armed."""
        event = {"armed": True, "account_name": "test", "account_number": "123"}
        reporter = IamKeyEnforcerReporter(mock_iam_client, event)

        boto_key = {"AccessKeyId": "AKIA123", "Status": "Active"}
        key = IaMAccessKey("AKIA123", 95, None, boto_key)
        user = IaMAccessKeyUser("test-user", False, key)

        status = reporter.enforce_action(DELETE_ACTION, user)

        assert status == "DELETED"
        mock_iam_client.delete_access_key.assert_called_once_with(
            UserName="test-user",
            AccessKeyId="AKIA123",
        )

    def test_enforce_delete_action_when_not_armed(self, mock_iam_client):
        """Test delete action not enforced when not armed."""
        event = {"armed": False, "account_name": "test", "account_number": "123"}
        reporter = IamKeyEnforcerReporter(mock_iam_client, event)

        boto_key = {"AccessKeyId": "AKIA123", "Status": "Active"}
        key = IaMAccessKey("AKIA123", 95, None, boto_key)
        user = IaMAccessKeyUser("test-user", False, key)

        status = reporter.enforce_action(DELETE_ACTION, user)

        assert status == "DELETED"
        mock_iam_client.delete_access_key.assert_not_called()

    def test_enforce_disable_action_when_armed(self, mock_iam_client):
        """Test disable action enforcement when armed."""
        event = {"armed": True, "account_name": "test", "account_number": "123"}
        reporter = IamKeyEnforcerReporter(mock_iam_client, event)

        boto_key = {"AccessKeyId": "AKIA456", "Status": "Active"}
        key = IaMAccessKey("AKIA456", 92, None, boto_key)
        user = IaMAccessKeyUser("admin-user", False, key)

        status = reporter.enforce_action(DISABLE_ACTION, user)

        assert status == "Active"
        mock_iam_client.update_access_key.assert_called_once_with(
            UserName="admin-user",
            AccessKeyId="AKIA456",
            Status="Inactive",
        )

    def test_enforce_exempt_action(self, mock_iam_client):
        """Test exempt action returns correct status."""
        event = {"armed": True, "account_name": "test", "account_number": "123"}
        reporter = IamKeyEnforcerReporter(mock_iam_client, event)

        boto_key = {"AccessKeyId": "AKIA789", "Status": "Active"}
        key = IaMAccessKey("AKIA789", 100, None, boto_key)
        user = IaMAccessKeyUser("exempt-user", True, key)

        status = reporter.enforce_action(EXEMPT_ACTION, user)

        assert status == "Active (Exempt)"

    def test_enforce_warn_action(self, mock_iam_client):
        """Test warn action returns current status."""
        event = {"armed": True, "account_name": "test", "account_number": "123"}
        reporter = IamKeyEnforcerReporter(mock_iam_client, event)

        boto_key = {"AccessKeyId": "AKIA999", "Status": "Active"}
        key = IaMAccessKey("AKIA999", 80, datetime.now(tz=UTC), boto_key)
        user = IaMAccessKeyUser("warn-user", False, key)

        status = reporter.enforce_action(WARN_ACTION, user)

        assert status == "Active"

    def test_enforce_action_handles_client_error(self, mock_iam_client, mocker):
        """Test enforce_action handles ClientError gracefully."""
        event = {"armed": True, "account_name": "test", "account_number": "123"}
        reporter = IamKeyEnforcerReporter(mock_iam_client, event)

        # Create a mock boto_key that raises ClientError when accessed
        mock_boto_key = mocker.MagicMock()
        mock_boto_key.__getitem__.side_effect = ClientError(
            {"Error": {"Code": "Test"}},
            "test",
        )

        key = IaMAccessKey("AKIA111", 95, None, mock_boto_key)
        user = IaMAccessKeyUser("error-user", False, key)

        status = reporter.enforce_action(DELETE_ACTION, user)

        assert "Error" in status
        assert reporter.has_errors is True


class TestProcessUserAccessKey:
    """Tests for process_user_access_key method."""

    def test_process_returns_none_for_no_action(self, mock_iam_client, mocker):
        """Test that NO_ACTION returns None."""
        event = {"armed": True, "account_name": "test", "account_number": "123"}
        reporter = IamKeyEnforcerReporter(mock_iam_client, event)

        # Use a young key that will result in NO_ACTION (younger than warning age)
        mocker.patch("iam_key_enforcer_reporter.KEY_AGE_WARNING", 75)

        boto_key = {"AccessKeyId": "AKIA123", "Status": "Active"}
        key = IaMAccessKey("AKIA123", 50, datetime.now(tz=UTC), boto_key)
        user = IaMAccessKeyUser("test-user", False, key)

        result = reporter.process_user_access_key(user)

        assert result is None

    def test_process_returns_report_row_for_action(self, mock_iam_client, mocker):
        """Test that action returns IAMKeyReportRow."""
        event = {
            "armed": True,
            "account_name": "test",
            "account_number": "123",
            "email_user_enabled": False,
        }
        reporter = IamKeyEnforcerReporter(mock_iam_client, event)

        # Set thresholds so key age of 80 results in WARN_ACTION
        mocker.patch("iam_key_enforcer_reporter.KEY_AGE_WARNING", 75)
        mocker.patch("iam_key_enforcer_reporter.KEY_AGE_INACTIVE", 90)
        mocker.patch("iam_key_enforcer_reporter.KEY_AGE_DELETE", 120)

        boto_key = {"AccessKeyId": "AKIA123", "Status": "Active"}
        key = IaMAccessKey("AKIA123", 80, datetime.now(tz=UTC), boto_key)
        user = IaMAccessKeyUser("test-user", False, key)

        result = reporter.process_user_access_key(user)

        assert isinstance(result, IAMKeyReportRow)
        assert result.user_name == "test-user"
        assert result.access_key_id == "AKIA123"
        assert result.action == WARN_ACTION


class TestEnforceAndReport:
    """Tests for enforce_and_report method."""

    def test_enforce_and_report_with_empty_credentials(self, mock_iam_client):
        """Test enforce_and_report with empty credentials report."""
        event = {"armed": True, "account_name": "test", "account_number": "123"}
        reporter = IamKeyEnforcerReporter(mock_iam_client, event)

        credentials_report = []

        result = reporter.enforce_and_report(credentials_report)

        assert not result

    def test_enforce_and_report_skips_root_user(self, mock_iam_client):
        """Test that root user is skipped."""
        event = {"armed": True, "account_name": "test", "account_number": "123"}
        reporter = IamKeyEnforcerReporter(mock_iam_client, event)

        # Use actual root user data - utils.root_user will correctly identify it
        credentials_report = [{"user": "<root_account>"}]

        result = reporter.enforce_and_report(credentials_report)

        assert not result

    def test_enforce_and_report_handles_client_error(self, mock_iam_client):
        """Test that ClientError is handled gracefully."""
        event = {
            "armed": True,
            "account_name": "test",
            "account_number": "123",
            "exempt_groups": None,
        }
        reporter = IamKeyEnforcerReporter(mock_iam_client, event)

        # Set up mock IAM client to raise ClientError when listing access keys
        mock_iam_client.list_access_keys.side_effect = ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "Access denied"}},
            "ListAccessKeys",
        )

        credentials_report = [
            {
                "user": "test-user",
                "access_key_1_active": "true",
                "access_key_1_last_rotated": "2024-01-01T00:00:00+00:00",
            }
        ]

        result = reporter.enforce_and_report(credentials_report)

        assert not result
        assert reporter.has_errors is True


class TestEnforce:
    """Tests for enforce method."""

    def test_enforce_with_no_report_rows(self, mock_iam_client, mocker):
        """Test enforce when no keys need action."""
        event = {
            "armed": True,
            "account_name": "test-account",
            "account_number": "123456789012",
        }
        reporter = IamKeyEnforcerReporter(mock_iam_client, event)

        mock_log_info = mocker.patch("iam_key_enforcer_reporter.LOG.info")

        # Empty credentials report - no users to process
        credentials_report = []

        reporter.enforce(credentials_report)

        mock_log_info.assert_called()
        assert not reporter.has_errors

    def test_enforce_with_report_rows(self, mock_iam_client, mocker):
        """Test enforce when keys need action."""
        event = {
            "armed": True,
            "account_name": "test-account",
            "account_number": "123456789012",
            "exempt_groups": None,
            "email_targets": ["admin@example.com"],
            "is_debug": False,
        }
        reporter = IamKeyEnforcerReporter(mock_iam_client, event)

        # Set up thresholds for warning action
        mocker.patch("iam_key_enforcer_reporter.KEY_AGE_WARNING", 75)
        mocker.patch("iam_key_enforcer_reporter.KEY_AGE_INACTIVE", 90)
        mocker.patch("iam_key_enforcer_reporter.KEY_AGE_DELETE", 120)
        mocker.patch("iam_key_enforcer_reporter.S3_ENABLED", False)

        # Mock external dependencies only (not internal methods)
        mock_admin_mailer = mocker.patch("iam_key_enforcer_reporter.AdminMailer")

        # Set up IAM client to return an old access key
        old_date = datetime.now(tz=UTC) - timedelta(days=80)
        mock_iam_client.list_access_keys.return_value = {
            "AccessKeyMetadata": [
                {
                    "AccessKeyId": "AKIA123",
                    "Status": "Active",
                    "CreateDate": old_date,
                }
            ]
        }
        mock_iam_client.get_access_key_last_used.return_value = {
            "AccessKeyLastUsed": {"LastUsedDate": datetime.now(tz=UTC)}
        }
        mock_iam_client.list_groups_for_user.return_value = {"Groups": []}

        credentials_report = [
            {
                "user": "test-user",
                "access_key_1_active": "true",
                "access_key_1_last_rotated": old_date.isoformat(),
            }
        ]

        reporter.enforce(credentials_report)

        # Verify AdminMailer was called
        mock_admin_mailer.assert_called_once()
        mock_admin_mailer.return_value.mail.assert_called_once()

    def test_enforce_raises_error_when_has_errors(self, mock_iam_client):
        """Test that enforce raises IamKeyEnforcerError when has_errors is True."""
        event = {
            "armed": True,
            "account_name": "test-account",
            "account_number": "123456789012",
            "exempt_groups": None,
        }
        reporter = IamKeyEnforcerReporter(mock_iam_client, event)

        # Set up a real error condition - IAM client raising an error
        mock_iam_client.list_access_keys.side_effect = ClientError(
            {"Error": {"Code": "ServiceError", "Message": "Service unavailable"}},
            "ListAccessKeys",
        )

        credentials_report = [
            {
                "user": "test-user",
                "access_key_1_active": "true",
                "access_key_1_last_rotated": "2024-01-01T00:00:00+00:00",
            }
        ]

        with pytest.raises(IamKeyEnforcerError):
            reporter.enforce(credentials_report)


class TestMailingAndStorageMethods:
    """Tests for mailing and storage methods."""

    def test_mail_admin_report_success(self, mock_iam_client, mocker):
        """Test successful admin report mailing."""
        event = {
            "armed": True,
            "account_name": "test",
            "account_number": "123",
            "email_targets": ["admin@test.com"],
            "is_debug": False,
        }
        reporter = IamKeyEnforcerReporter(mock_iam_client, event)

        mock_admin_mailer = mocker.patch(
            "iam_key_enforcer_reporter.AdminMailer",
        )

        template_data = {"key_report_contents": []}

        reporter.mail_admin_report(template_data)

        mock_admin_mailer.assert_called_once()
        mock_admin_mailer.return_value.mail.assert_called_once()

    def test_mail_admin_report_handles_error(self, mock_iam_client, mocker):
        """Test mail_admin_report handles ClientError."""
        event = {
            "armed": True,
            "account_name": "test",
            "account_number": "123",
            "email_targets": ["admin@test.com"],
            "is_debug": False,
        }
        reporter = IamKeyEnforcerReporter(mock_iam_client, event)

        mock_admin_mailer = mocker.patch(
            "iam_key_enforcer_reporter.AdminMailer",
        )
        mock_admin_mailer.return_value.mail.side_effect = ClientError(
            {"Error": {"Code": "Test"}},
            "test",
        )

        template_data = {"key_report_contents": []}

        reporter.mail_admin_report(template_data)

        assert reporter.has_errors is True

    def test_store_admin_report_when_s3_disabled(self, mock_iam_client, mocker):
        """Test store_admin_report when S3 is disabled."""
        event = {
            "armed": True,
            "account_name": "test",
            "account_number": "123",
        }
        reporter = IamKeyEnforcerReporter(mock_iam_client, event)

        mocker.patch("iam_key_enforcer_reporter.S3_ENABLED", False)
        mock_store = mocker.patch("iam_key_enforcer_reporter.utils.store_in_s3")
        mock_log_info = mocker.patch("iam_key_enforcer_reporter.LOG.info")

        reporter.store_admin_report({})

        mock_log_info.assert_called_once()
        mock_store.assert_not_called()

    def test_store_admin_report_when_s3_enabled(self, mock_iam_client, mocker):
        """Test store_admin_report when S3 is enabled."""
        event = {
            "armed": True,
            "account_name": "test",
            "account_number": "123456789012",
        }
        reporter = IamKeyEnforcerReporter(mock_iam_client, event)

        mocker.patch("iam_key_enforcer_reporter.S3_ENABLED", True)
        mock_store = mocker.patch("iam_key_enforcer_reporter.utils.store_in_s3")

        template_data = {"key_report_contents": []}

        reporter.store_admin_report(template_data)

        mock_store.assert_called_once_with("123456789012", template_data)


class TestTemplateDataMethods:
    """Tests for template data building methods."""

    def test_admin_template_data(self, mock_iam_client, mocker):
        """Test admin_template_data builds correct structure."""
        event = {
            "armed": True,
            "account_name": "test-account",
            "account_number": "123456789012",
            "exempt_groups": ["admins"],
        }
        reporter = IamKeyEnforcerReporter(mock_iam_client, event)

        mocker.patch(
            "iam_key_enforcer_reporter.optional_email_template_data",
            return_value={"extra": "data"},
        )

        enforcer_report = [{"user": "test"}]

        result = reporter.admin_template_data(enforcer_report)

        assert result["account_number"] == "123456789012"
        assert result["account_name"] == "test-account"
        assert result["key_report_contents"] == enforcer_report
        assert "key_age_inactive" in result
        assert "key_age_delete" in result
        assert "key_age_warning" in result
        assert "key_use_threshold" in result
        assert result["extra"] == "data"

    def test_user_email_template_data(self, mock_iam_client, mocker):
        """Test user_email_template_data builds correct structure."""
        event = {"armed": True, "account_name": "test", "account_number": "123"}
        reporter = IamKeyEnforcerReporter(mock_iam_client, event)

        mocker.patch(
            "iam_key_enforcer_reporter.utils.action_armed_state_message",
            return_value="has been deleted",
        )
        mocker.patch(
            "iam_key_enforcer_reporter.optional_email_template_data",
            return_value={},
        )

        boto_key = {"AccessKeyId": "AKIA123", "Status": "Active"}
        key = IaMAccessKey("AKIA123", 95, None, boto_key)
        user = IaMAccessKeyUser("test-user", False, key)

        result = reporter.user_email_template_data(user, DELETE_ACTION)

        assert result["armed_state_msg"] == "has been deleted"
        assert result["access_key_id"] == "AKIA123"
        assert result["action"] == DELETE_ACTION
        assert result["user_name"] == "test-user"


class TestErrorMethod:
    """Tests for error method."""

    def test_error_sets_has_errors_flag(self, mock_iam_client, mocker):
        """Test that error method sets has_errors to True."""
        event = {"armed": True, "account_name": "test", "account_number": "123"}
        reporter = IamKeyEnforcerReporter(mock_iam_client, event)

        # Mock LOG.error to avoid actual logging
        mocker.patch("iam_key_enforcer_reporter.LOG.error")

        reporter.error("Test error message")

        assert reporter.has_errors is True

    def test_error_logs_message_when_provided(self, mock_iam_client, mocker):
        """Test that error logs message when provided."""
        event = {"armed": True, "account_name": "test", "account_number": "123"}
        reporter = IamKeyEnforcerReporter(mock_iam_client, event)

        mock_log_error = mocker.patch("iam_key_enforcer_reporter.LOG.error")

        reporter.error("Custom error message")

        mock_log_error.assert_called_with("Custom error message")

    def test_error_without_message_does_not_log(self, mock_iam_client, mocker):
        """Test that error without message doesn't call LOG.error."""
        event = {"armed": True, "account_name": "test", "account_number": "123"}
        reporter = IamKeyEnforcerReporter(mock_iam_client, event)

        mock_log_error = mocker.patch("iam_key_enforcer_reporter.LOG.error")

        reporter.error()

        assert reporter.has_errors is True
        mock_log_error.assert_not_called()


class TestMultipleUsersWithErrorInMiddle:
    """Tests for processing multiple users when an error occurs in the middle."""

    def test_enforce_multiple_users_error_in_middle_continues_and_raises(
        self, mock_iam_client, mocker
    ):
        """
        Test that when processing multiple users, if an error occurs for one user.

        Processing continues for remaining users, a report is generated, and then
        an exception is raised at the end.
        """
        event = {
            "armed": True,
            "account_name": "test-account",
            "account_number": "123456789012",
            "exempt_groups": None,
            "email_targets": ["admin@example.com"],
            "is_debug": False,
        }
        reporter = IamKeyEnforcerReporter(mock_iam_client, event)

        # Set up thresholds so all keys get a WARN action
        mocker.patch("iam_key_enforcer_reporter.KEY_AGE_WARNING", 75)
        mocker.patch("iam_key_enforcer_reporter.KEY_AGE_INACTIVE", 90)
        mocker.patch("iam_key_enforcer_reporter.KEY_AGE_DELETE", 120)
        mocker.patch("iam_key_enforcer_reporter.S3_ENABLED", False)

        # Mock AdminMailer to track that mail was called
        mock_admin_mailer = mocker.patch("iam_key_enforcer_reporter.AdminMailer")

        # Set up dates for access keys
        old_date = datetime.now(tz=UTC) - timedelta(days=80)

        # Configure mock IAM client to succeed for user1 and user3, but fail for user2
        def list_access_keys_side_effect(user_name):
            if user_name == "user2":
                raise ClientError(
                    {"Error": {"Code": "ServiceError", "Message": "Service error"}},
                    "ListAccessKeys",
                )
            return {
                "AccessKeyMetadata": [
                    {
                        "AccessKeyId": f"AKIA{user_name.upper()}",
                        "Status": "Active",
                        "CreateDate": old_date,
                    }
                ]
            }

        mock_iam_client.list_access_keys.side_effect = list_access_keys_side_effect
        mock_iam_client.get_access_key_last_used.return_value = {
            "AccessKeyLastUsed": {"LastUsedDate": datetime.now(tz=UTC)}
        }
        mock_iam_client.list_groups_for_user.return_value = {"Groups": []}

        # Create credentials report with 3 users
        credentials_report = [
            {"user": "user1"},
            {"user": "user2"},  # This user will fail
            {"user": "user3"},
        ]

        # Execute enforce - should raise IamKeyEnforcerError after processing all users
        with pytest.raises(IamKeyEnforcerError) as excinfo:
            reporter.enforce(credentials_report)

        # Verify the error message is correct
        assert "Errors occurred during processing" in str(excinfo.value)

        # Verify has_errors flag was set
        assert reporter.has_errors is True

        # Verify AdminMailer was called (report was still generated and sent)
        mock_admin_mailer.assert_called_once()
        mock_admin_mailer.return_value.mail.assert_called_once()

        # Verify list_access_keys was called for all 3 users
        assert mock_iam_client.list_access_keys.call_count == 3

    def test_enforce_and_report_continues_after_user_error(
        self, mock_iam_client, mocker
    ):
        """Test that enforce_and_report processes all users even if one fails."""
        event = {
            "armed": True,
            "account_name": "test-account",
            "account_number": "123456789012",
            "exempt_groups": None,
        }
        reporter = IamKeyEnforcerReporter(mock_iam_client, event)

        # Set up thresholds
        mocker.patch("iam_key_enforcer_reporter.KEY_AGE_WARNING", 75)
        mocker.patch("iam_key_enforcer_reporter.KEY_AGE_INACTIVE", 90)
        mocker.patch("iam_key_enforcer_reporter.KEY_AGE_DELETE", 120)

        old_date = datetime.now(tz=UTC) - timedelta(days=80)

        # First user succeeds, second fails, third succeeds
        call_count = [0]

        def list_access_keys_side_effect(user_name):
            call_count[0] += 1
            if user_name == "failing-user":
                raise ClientError(
                    {"Error": {"Code": "AccessDenied", "Message": "Access denied"}},
                    "ListAccessKeys",
                )
            return {
                "AccessKeyMetadata": [
                    {
                        "AccessKeyId": f"AKIA{call_count[0]:04d}",
                        "Status": "Active",
                        "CreateDate": old_date,
                    }
                ]
            }

        mock_iam_client.list_access_keys.side_effect = list_access_keys_side_effect
        mock_iam_client.get_access_key_last_used.return_value = {
            "AccessKeyLastUsed": {"LastUsedDate": datetime.now(tz=UTC)}
        }
        mock_iam_client.list_groups_for_user.return_value = {"Groups": []}

        credentials_report = [
            {"user": "good-user-1"},
            {"user": "failing-user"},
            {"user": "good-user-2"},
        ]

        result = reporter.enforce_and_report(credentials_report)

        # Should have results for 2 successful users
        assert len(result) == 2
        assert reporter.has_errors is True

    def test_enforce_processes_all_users_and_keys_before_raising(
        self, mock_iam_client, mocker
    ):
        """
        Test all users processed even when errors.

        Test that when multiple users are processed and some raise errors,
        all users are still processed, a report is generated, and then an exception
        """
        event = {
            "armed": True,
            "account_name": "test-account",
            "account_number": "123456789012",
            "exempt_groups": None,
            "email_targets": ["admin@example.com"],
            "is_debug": True,
        }
        reporter = IamKeyEnforcerReporter(mock_iam_client, event)

        mocker.patch("iam_key_enforcer_reporter.KEY_AGE_WARNING", 75)
        mocker.patch("iam_key_enforcer_reporter.KEY_AGE_INACTIVE", 90)
        mocker.patch("iam_key_enforcer_reporter.KEY_AGE_DELETE", 120)
        mocker.patch("iam_key_enforcer_reporter.S3_ENABLED", False)
        mock_admin_mailer = mocker.patch("iam_key_enforcer_reporter.AdminMailer")

        old_date = datetime.now(tz=UTC) - timedelta(days=80)

        # Errors for users 1 and 3 (at different points)
        call_counter = [0]

        def list_access_keys_side_effect(user_name):
            call_counter[0] += 1
            if user_name in ("error-user-1", "error-user-2"):
                raise ClientError(
                    {"Error": {"Code": "Error", "Message": "Error"}},
                    "ListAccessKeys",
                )
            return {
                "AccessKeyMetadata": [
                    {
                        "AccessKeyId": f"AKIA{call_counter[0]:04d}",
                        "Status": "Active",
                        "CreateDate": old_date,
                    }
                ]
            }

        mock_iam_client.list_access_keys.side_effect = list_access_keys_side_effect
        mock_iam_client.get_access_key_last_used.return_value = {
            "AccessKeyLastUsed": {"LastUsedDate": datetime.now(tz=UTC)}
        }
        mock_iam_client.list_groups_for_user.return_value = {"Groups": []}

        credentials_report = [
            {"user": "good-user-1"},
            {"user": "error-user-1"},
            {"user": "good-user-2"},
            {"user": "error-user-2"},
            {"user": "good-user-3"},
        ]

        with pytest.raises(IamKeyEnforcerError):
            reporter.enforce(credentials_report)

        # All 5 users should have been attempted
        assert mock_iam_client.list_access_keys.call_count == 5

        # Admin mailer should still be called (3 successful users)
        mock_admin_mailer.assert_called_once()
        mock_admin_mailer.return_value.mail.assert_called_once()
