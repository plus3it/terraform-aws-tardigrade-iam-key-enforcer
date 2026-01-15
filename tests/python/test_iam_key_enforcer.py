"""
Tests for IAM Key Enforcer Module.

This module contains comprehensive unit tests for the IAM key enforcer,
including credential report generation, IAM client creation, and CLI validators.

"""

from argparse import ArgumentTypeError
from unittest.mock import MagicMock

import pytest
from errors import GenerateCredentialReportThrottleError
from iam_key_enforcer import (
    account_number,
    exception_hook,
    generate_credential_report,
    get_client_iam,
    get_credential_report,
    iam_role_arn,
    lambda_handler,
    main,
)


class TestExceptionHook:
    """Tests for exception_hook function."""

    def test_exception_hook_logs_exception(self, mocker):
        """Test that exception_hook logs exceptions."""
        mock_log_exception = mocker.patch("iam_key_enforcer.LOG.exception")

        exc_type = ValueError
        exc_value = ValueError("test error")
        exc_traceback = None

        exception_hook(exc_type, exc_value, exc_traceback)

        mock_log_exception.assert_called_once_with(
            "%s: %s",
            "ValueError",
            exc_value,
            exc_info=(exc_type, exc_value, exc_traceback),
        )

    def test_exception_hook_different_exception_types(self, mocker):
        """Test exception_hook with different exception types."""
        mock_log_exception = mocker.patch("iam_key_enforcer.LOG.exception")

        exc_type = KeyError
        exc_value = KeyError("missing key")
        exc_traceback = None

        exception_hook(exc_type, exc_value, exc_traceback)

        mock_log_exception.assert_called_once()
        assert mock_log_exception.call_args[0][0] == "%s: %s"
        assert mock_log_exception.call_args[0][1] == "KeyError"


class TestLambdaHandler:
    """Tests for lambda_handler function."""

    def test_lambda_handler_calls_main(self, mocker):
        """Test that lambda_handler executes the full workflow."""
        mock_context = MagicMock()
        mock_context.function_name = "test-function"

        # Mock external dependencies only, not internal functions
        mock_aws_manager = mocker.patch("iam_key_enforcer.aws")
        mock_session = MagicMock()
        mock_aws_manager.session = mock_session

        mock_assumed_session = MagicMock()
        mock_iam_client = MagicMock()
        mock_assumed_session.client.return_value = mock_iam_client

        mocker.patch("iam_key_enforcer.assume_role", return_value=mock_assumed_session)
        mocker.patch(
            "iam_key_enforcer.generate_lambda_session_name", return_value="test-session"
        )

        # Mock IAM client responses
        mock_iam_client.generate_credential_report.return_value = {"State": "COMPLETE"}
        csv_content = "user,arn\ntest-user,arn:aws:iam::123456789012:user/test-user\n"
        mock_iam_client.get_credential_report.return_value = {
            "Content": csv_content.encode("utf-8")
        }
        mock_iam_client.list_access_keys.return_value = {"AccessKeyMetadata": []}

        mock_enforcer_class = mocker.patch("iam_key_enforcer.IamKeyEnforcerReporter")

        event = {
            "role_arn": "arn:aws:iam::123456789012:role/test-role",
            "account_number": "123456789012",
            "account_name": "test-account",
            "armed": False,
            "email_user_enabled": True,
            "email_targets": ["admin@example.com"],
            "exempt_groups": ["admins"],
        }

        lambda_handler(event, mock_context)

        # Verify the enforcer was created and enforce was called
        mock_enforcer_class.assert_called_once_with(mock_iam_client, event)
        mock_enforcer_class.return_value.enforce.assert_called_once()

    def test_lambda_handler_with_minimal_event(self, mocker):
        """Test lambda_handler with minimal event data."""
        mock_context = MagicMock()
        mock_context.function_name = "minimal-function"

        # Mock external dependencies only
        mock_aws_manager = mocker.patch("iam_key_enforcer.aws")
        mock_session = MagicMock()
        mock_aws_manager.session = mock_session

        mock_assumed_session = MagicMock()
        mock_iam_client = MagicMock()
        mock_assumed_session.client.return_value = mock_iam_client

        mocker.patch("iam_key_enforcer.assume_role", return_value=mock_assumed_session)
        mocker.patch(
            "iam_key_enforcer.generate_lambda_session_name",
            return_value="minimal-session",
        )

        # Mock IAM client responses
        mock_iam_client.generate_credential_report.return_value = {"State": "COMPLETE"}
        mock_iam_client.get_credential_report.return_value = {"Content": b"user,arn\n"}

        mock_enforcer_class = mocker.patch("iam_key_enforcer.IamKeyEnforcerReporter")

        event = {
            "role_arn": "arn:aws:iam::999888777666:role/minimal-role",
        }

        lambda_handler(event, mock_context)

        # Verify the enforcer was created and enforce was called
        mock_enforcer_class.assert_called_once()
        mock_enforcer_class.return_value.enforce.assert_called_once()


class TestGenerateCredentialReport:
    """Tests for generate_credential_report function."""

    def test_generate_credential_report_complete_on_first_try(self, mocker):
        """Test credential report generation succeeds immediately."""
        mock_iam = mocker.MagicMock()
        mock_iam.generate_credential_report.return_value = {"State": "COMPLETE"}

        result = generate_credential_report(mock_iam, 0)

        assert result is None
        mock_iam.generate_credential_report.assert_called_once()

    def test_generate_credential_report_retry_then_complete(self, mocker):
        """Test credential report generation succeeds after retries."""
        mock_iam = mocker.MagicMock()
        mock_iam.generate_credential_report.side_effect = [
            {"State": "STARTED"},
            {"State": "INPROGRESS"},
            {"State": "COMPLETE"},
        ]
        mock_sleep = mocker.patch("iam_key_enforcer.sleep")
        mock_log_info = mocker.patch("iam_key_enforcer.LOG.info")

        result = generate_credential_report(mock_iam, 0)

        assert result is None
        assert mock_iam.generate_credential_report.call_count == 3
        assert mock_sleep.call_count == 2
        mock_sleep.assert_called_with(10)
        assert mock_log_info.call_count >= 2

    def test_generate_credential_report_max_attempts_exceeded(self, mocker):
        """Test credential report generation fails after max attempts."""
        mock_iam = mocker.MagicMock()
        mock_iam.generate_credential_report.return_value = {"State": "STARTED"}
        mock_sleep = mocker.patch("iam_key_enforcer.sleep")

        with pytest.raises(GenerateCredentialReportThrottleError) as excinfo:
            generate_credential_report(mock_iam, 0)

        assert "Credential report generation throttled" in str(excinfo.value)
        # Default max_attempts is 5, so should try 5 times
        assert mock_iam.generate_credential_report.call_count == 5
        assert mock_sleep.call_count == 4

    def test_generate_credential_report_custom_max_attempts(self, mocker):
        """Test credential report generation with custom max attempts."""
        # Create a fresh mock for this test
        mock_iam = MagicMock()
        mock_iam.generate_credential_report.return_value = {"State": "STARTED"}
        mock_sleep = mocker.patch("iam_key_enforcer.sleep")
        mocker.patch("iam_key_enforcer.LOG.info")

        with pytest.raises(GenerateCredentialReportThrottleError):
            generate_credential_report(mock_iam, 0, max_attempts=3)

        # With max_attempts=3, starting at counter=0:
        # Call 1: counter=0->1, 1<3, recurse
        # Call 2: counter=1->2, 2<3, recurse
        # Call 3: counter=2->3, 3<3 is False, raise
        assert mock_iam.generate_credential_report.call_count == 3
        assert mock_sleep.call_count == 2

    def test_generate_credential_report_starting_counter(self, mocker):
        """Test credential report generation with non-zero starting counter."""
        mock_iam = mocker.MagicMock()
        mock_iam.generate_credential_report.return_value = {"State": "STARTED"}
        mock_sleep = mocker.patch("iam_key_enforcer.sleep")
        mocker.patch("iam_key_enforcer.LOG.info")

        with pytest.raises(GenerateCredentialReportThrottleError):
            generate_credential_report(mock_iam, 2, max_attempts=3)

        # Starting at counter=2, max_attempts=3:
        # Call 1: counter=2->3, 3<3 is False, raise
        # So only 1 call total
        assert mock_iam.generate_credential_report.call_count == 1
        assert mock_sleep.call_count == 0


class TestGetCredentialReport:
    """Tests for get_credential_report function."""

    def test_get_credential_report_success(self, mocker):
        """Test successfully getting and parsing credential report."""
        mock_iam = mocker.MagicMock()

        # Mock IAM client to return COMPLETE status and report content
        mock_iam.generate_credential_report.return_value = {"State": "COMPLETE"}
        csv_content = (
            "user,arn,user_creation_time,password_enabled,access_key_1_active\n"
            "test-user,arn:aws:iam::123456789012:user/test-user,"
            "2025-01-01T00:00:00+00:00,true,true\n"
        )
        mock_iam.get_credential_report.return_value = {
            "Content": csv_content.encode("utf-8"),
        }

        result = get_credential_report(mock_iam, 0)

        assert len(result) == 1
        assert result[0]["user"] == "test-user"
        assert result[0]["password_enabled"] == "true"
        mock_iam.generate_credential_report.assert_called_once()
        mock_iam.get_credential_report.assert_called_once()

    def test_get_credential_report_multiple_users(self, mocker):
        """Test credential report with multiple users."""
        mock_iam = mocker.MagicMock()

        # Mock IAM client responses
        mock_iam.generate_credential_report.return_value = {"State": "COMPLETE"}
        csv_content = (
            "user,arn,access_key_1_active,access_key_2_active\n"
            "user1,arn:aws:iam::123456789012:user/user1,true,false\n"
            "user2,arn:aws:iam::123456789012:user/user2,false,false\n"
            "user3,arn:aws:iam::123456789012:user/user3,true,true\n"
        )
        mock_iam.get_credential_report.return_value = {
            "Content": csv_content.encode("utf-8"),
        }

        result = get_credential_report(mock_iam)

        assert len(result) == 3
        assert result[0]["user"] == "user1"
        assert result[1]["user"] == "user2"
        assert result[2]["user"] == "user3"

    def test_get_credential_report_empty(self, mocker):
        """Test credential report with no users."""
        mock_iam = mocker.MagicMock()

        # Mock IAM client responses
        mock_iam.generate_credential_report.return_value = {"State": "COMPLETE"}
        csv_content = "user,arn,access_key_1_active\n"
        mock_iam.get_credential_report.return_value = {
            "Content": csv_content.encode("utf-8"),
        }

        result = get_credential_report(mock_iam)

        assert len(result) == 0

    def test_get_credential_report_custom_counter(self, mocker):
        """Test credential report with custom report counter."""
        mock_iam = mocker.MagicMock()

        # Mock IAM client responses
        mock_iam.generate_credential_report.return_value = {"State": "COMPLETE"}
        csv_content = "user,arn\ntest,arn:aws:iam::123456789012:user/test\n"
        mock_iam.get_credential_report.return_value = {
            "Content": csv_content.encode("utf-8"),
        }

        result = get_credential_report(mock_iam, report_counter=3)

        # Verify generate_credential_report was called with the custom counter
        mock_iam.generate_credential_report.assert_called_once()
        assert len(result) == 1


class TestGetClientIam:
    """Tests for get_client_iam function."""

    def test_get_client_iam_creates_client(self, mocker):
        """Test that get_client_iam creates IAM client with assumed role."""
        mock_aws_manager = mocker.patch("iam_key_enforcer.aws")
        mock_session = MagicMock()
        mock_aws_manager.session = mock_session

        mock_assumed_session = MagicMock()
        mock_iam_client = MagicMock()
        mock_assumed_session.client.return_value = mock_iam_client

        mock_assume_role = mocker.patch(
            "iam_key_enforcer.assume_role",
            return_value=mock_assumed_session,
        )
        mock_generate_name = mocker.patch(
            "iam_key_enforcer.generate_lambda_session_name",
            return_value="test-session-name",
        )

        role_arn = "arn:aws:iam::123456789012:role/test-role"
        function_name = "test-function"

        result = get_client_iam(role_arn, function_name)

        assert result == mock_iam_client
        mock_generate_name.assert_called_once_with(function_name)
        mock_assume_role.assert_called_once_with(
            mock_session,
            role_arn,
            RoleSessionName="test-session-name",
        )
        mock_assumed_session.client.assert_called_once_with("iam")

    def test_get_client_iam_different_role(self, mocker):
        """Test get_client_iam with different role ARN."""
        mock_aws_manager = mocker.patch("iam_key_enforcer.aws")
        mock_session = MagicMock()
        mock_aws_manager.session = mock_session

        mock_assumed_session = MagicMock()
        mock_iam_client = MagicMock()
        mock_assumed_session.client.return_value = mock_iam_client

        mocker.patch("iam_key_enforcer.assume_role", return_value=mock_assumed_session)
        mocker.patch(
            "iam_key_enforcer.generate_lambda_session_name",
            return_value="session-2",
        )

        role_arn = "arn:aws:iam::999888777666:role/different-role"
        function_name = "different-function"

        result = get_client_iam(role_arn, function_name)

        assert result == mock_iam_client


class TestMain:
    """Tests for main function."""

    def test_main_executes_enforcer(self, mocker):
        """Test that main function executes the enforcer."""
        # Mock external AWS dependencies
        mock_aws_manager = mocker.patch("iam_key_enforcer.aws")
        mock_session = MagicMock()
        mock_aws_manager.session = mock_session

        mock_assumed_session = MagicMock()
        mock_iam_client = MagicMock()
        mock_assumed_session.client.return_value = mock_iam_client

        mocker.patch("iam_key_enforcer.assume_role", return_value=mock_assumed_session)
        mocker.patch(
            "iam_key_enforcer.generate_lambda_session_name", return_value="test-session"
        )

        # Mock IAM client responses
        mock_iam_client.generate_credential_report.return_value = {"State": "COMPLETE"}
        csv_content = "user,arn\ntest-user,arn:aws:iam::123456789012:user/test-user\n"
        mock_iam_client.get_credential_report.return_value = {
            "Content": csv_content.encode("utf-8")
        }

        # Only mock the enforcer class (external dependency)
        mock_enforcer_class = mocker.patch("iam_key_enforcer.IamKeyEnforcerReporter")

        role_arn = "arn:aws:iam::123456789012:role/test-role"
        event = {
            "account_number": "123456789012",
            "account_name": "test-account",
            "armed": True,
        }
        function_name = "test-function"

        main(role_arn, event, function_name)

        # Verify the enforcer was created with correct parameters and enforce was called
        mock_enforcer_class.assert_called_once_with(mock_iam_client, event)
        assert mock_enforcer_class.return_value.enforce.call_count == 1
        # Verify the credential report was passed to enforce
        enforce_call_args = mock_enforcer_class.return_value.enforce.call_args[0][0]
        assert len(enforce_call_args) == 1
        assert enforce_call_args[0]["user"] == "test-user"

    def test_main_with_different_event(self, mocker):
        """Test main function with different event data."""
        # Mock external AWS dependencies
        mock_aws_manager = mocker.patch("iam_key_enforcer.aws")
        mock_session = MagicMock()
        mock_aws_manager.session = mock_session

        mock_assumed_session = MagicMock()
        mock_iam_client = MagicMock()
        mock_assumed_session.client.return_value = mock_iam_client

        mocker.patch("iam_key_enforcer.assume_role", return_value=mock_assumed_session)
        mocker.patch(
            "iam_key_enforcer.generate_lambda_session_name",
            return_value="another-session",
        )

        # Mock IAM client to return empty credential report
        mock_iam_client.generate_credential_report.return_value = {"State": "COMPLETE"}
        mock_iam_client.get_credential_report.return_value = {"Content": b"user,arn\n"}

        # Only mock the enforcer class
        mock_enforcer_class = mocker.patch("iam_key_enforcer.IamKeyEnforcerReporter")

        role_arn = "arn:aws:iam::999888777666:role/another-role"
        event = {
            "account_number": "999888777666",
            "account_name": "another-account",
            "armed": False,
            "email_user_enabled": False,
        }
        function_name = "another-function"

        main(role_arn, event, function_name)

        # Verify enforcer was called with empty credential list
        mock_enforcer_class.return_value.enforce.assert_called_once_with([])


class TestAccountNumber:
    """Tests for account_number validator."""

    def test_account_number_valid(self):
        """Test valid 12-digit account number."""
        result = account_number("123456789012")
        assert result == "123456789012"

    def test_account_number_with_leading_zeros(self):
        """Test account number with leading zeros."""
        result = account_number("000000000001")
        assert result == "000000000001"

    def test_account_number_all_zeros(self):
        """Test account number with all zeros."""
        result = account_number("000000000000")
        assert result == "000000000000"

    def test_account_number_too_short(self):
        """Test account number that is too short."""
        with pytest.raises(ArgumentTypeError) as excinfo:
            account_number("12345678901")

        assert "must be exactly 12 digits" in str(excinfo.value)

    def test_account_number_too_long(self):
        """Test account number that is too long."""
        with pytest.raises(ArgumentTypeError) as excinfo:
            account_number("1234567890123")

        assert "must be exactly 12 digits" in str(excinfo.value)

    def test_account_number_contains_letters(self):
        """Test account number containing letters."""
        with pytest.raises(ArgumentTypeError) as excinfo:
            account_number("12345678901a")

        assert "must be exactly 12 digits" in str(excinfo.value)

    def test_account_number_contains_special_chars(self):
        """Test account number containing special characters."""
        with pytest.raises(ArgumentTypeError) as excinfo:
            account_number("123456-78901")

        assert "must be exactly 12 digits" in str(excinfo.value)

    def test_account_number_empty_string(self):
        """Test empty string as account number."""
        with pytest.raises(ArgumentTypeError) as excinfo:
            account_number("")

        assert "must be exactly 12 digits" in str(excinfo.value)


class TestIamRoleArn:
    """Tests for iam_role_arn validator."""

    def test_iam_role_arn_valid_aws(self):
        """Test valid IAM role ARN in aws partition."""
        arn = "arn:aws:iam::123456789012:role/test-role"
        result = iam_role_arn(arn)
        assert result == arn

    def test_iam_role_arn_valid_aws_us_gov(self):
        """Test valid IAM role ARN in aws-us-gov partition."""
        arn = "arn:aws-us-gov:iam::123456789012:role/test-role"
        result = iam_role_arn(arn)
        assert result == arn

    def test_iam_role_arn_with_path(self):
        """Test IAM role ARN with role path."""
        arn = "arn:aws:iam::123456789012:role/path/to/test-role"
        result = iam_role_arn(arn)
        assert result == arn

    def test_iam_role_arn_with_deep_path(self):
        """Test IAM role ARN with deep role path."""
        arn = "arn:aws:iam::123456789012:role/path/to/deep/test-role"
        result = iam_role_arn(arn)
        assert result == arn

    def test_iam_role_arn_with_special_chars(self):
        """Test IAM role ARN with special characters in role name."""
        arn = "arn:aws:iam::123456789012:role/test-role_with-special.chars@123"
        result = iam_role_arn(arn)
        assert result == arn

    def test_iam_role_arn_invalid_partition(self):
        """Test IAM role ARN with invalid partition."""
        arn = "arn:aws-cn:iam::123456789012:role/test-role"
        with pytest.raises(ArgumentTypeError) as excinfo:
            iam_role_arn(arn)

        assert "invalid IAM role ARN" in str(excinfo.value)

    def test_iam_role_arn_invalid_account_number(self):
        """Test IAM role ARN with invalid account number."""
        arn = "arn:aws:iam::12345:role/test-role"
        with pytest.raises(ArgumentTypeError) as excinfo:
            iam_role_arn(arn)

        assert "invalid IAM role ARN" in str(excinfo.value)

    def test_iam_role_arn_user_instead_of_role(self):
        """Test IAM user ARN instead of role ARN."""
        arn = "arn:aws:iam::123456789012:user/test-user"
        with pytest.raises(ArgumentTypeError) as excinfo:
            iam_role_arn(arn)

        assert "invalid IAM role ARN" in str(excinfo.value)

    def test_iam_role_arn_missing_role_name(self):
        """Test IAM role ARN missing role name."""
        arn = "arn:aws:iam::123456789012:role/"
        with pytest.raises(ArgumentTypeError) as excinfo:
            iam_role_arn(arn)

        assert "invalid IAM role ARN" in str(excinfo.value)

    def test_iam_role_arn_not_arn_format(self):
        """Test invalid ARN format."""
        arn = "invalid-arn"
        with pytest.raises(ArgumentTypeError) as excinfo:
            iam_role_arn(arn)

        assert "invalid IAM role ARN" in str(excinfo.value)

    def test_iam_role_arn_empty_string(self):
        """Test empty string as role ARN."""
        with pytest.raises(ArgumentTypeError) as excinfo:
            iam_role_arn("")

        assert "invalid IAM role ARN" in str(excinfo.value)

    def test_iam_role_arn_wrong_service(self):
        """Test ARN with wrong service (not IAM)."""
        arn = "arn:aws:s3:::my-bucket"
        with pytest.raises(ArgumentTypeError) as excinfo:
            iam_role_arn(arn)

        assert "invalid IAM role ARN" in str(excinfo.value)
