"""
Tests for Mailers.

This module contains comprehensive unit tests for the mailer classes and functions,
including AdminMailer, UserMailer, and email utility functions.

"""

import json

from mailers import (
    AdminMailer,
    UserMailer,
    get_event_email_list,
    get_to_addresses,
    get_user_email_from_tags,
    log_invalid_email,
    optional_email_template_data,
    send_email,
    validate_email,
)


class TestValidateEmail:
    """Tests for validate_email function."""

    def test_valid_email_simple(self):
        """Test validation of simple valid email."""
        assert validate_email("user@example.com") is True

    def test_valid_email_with_subdomain(self):
        """Test validation of email with subdomain."""
        assert validate_email("user@mail.example.com") is True

    def test_valid_email_with_numbers(self):
        """Test validation of email with numbers."""
        assert validate_email("user123@example456.com") is True

    def test_invalid_email_no_at(self):
        """Test validation fails for email without @."""
        assert validate_email("userexample.com") is False

    def test_invalid_email_no_domain(self):
        """Test validation fails for email without domain."""
        assert validate_email("user@") is False

    def test_invalid_email_empty_string(self):
        """Test validation fails for empty string."""
        assert validate_email("") is False

    def test_invalid_email_none(self):
        """Test validation fails for None."""
        assert validate_email(None) is False

    def test_invalid_email_spaces(self):
        """Test validation fails for email with spaces."""
        assert validate_email("user @example.com") is False

    def test_invalid_email_no_local_part(self):
        """Test validation fails for email without local part."""
        assert validate_email("@example.com") is False


class TestLogInvalidEmail:
    """Tests for log_invalid_email function."""

    def test_log_invalid_email_user(self, mocker):
        """Test logging invalid user email."""
        mock_log_error = mocker.patch("mailers.LOG.error")

        log_invalid_email("user (test-user)", "invalid-email")

        mock_log_error.assert_called_once_with(
            "Invalid %s email found - email: %s",
            "user (test-user)",
            "invalid-email",
        )

    def test_log_invalid_email_admin(self, mocker):
        """Test logging invalid admin email."""
        mock_log_error = mocker.patch("mailers.LOG.error")

        log_invalid_email("admin", "bad@email")

        mock_log_error.assert_called_once_with(
            "Invalid %s email found - email: %s",
            "admin",
            "bad@email",
        )


class TestGetUserEmailFromTags:
    """Tests for get_user_email_from_tags function."""

    def test_get_email_from_tags_success(self, mocker):
        """Test successfully retrieving email from tags."""
        mocker.patch("mailers.EMAIL_TAG", "email")
        tags = {
            "Tags": [
                {"Key": "email", "Value": "user@example.com"},
                {"Key": "Name", "Value": "test-user"},
            ],
        }

        result = get_user_email_from_tags("test-user", tags, is_debug=False)

        assert result == "user@example.com"

    def test_get_email_from_tags_case_insensitive(self, mocker):
        """Test email tag matching is case insensitive."""
        mocker.patch("mailers.EMAIL_TAG", "email")
        tags = {
            "Tags": [
                {"Key": "EMAIL", "Value": "user@example.com"},
            ],
        }

        result = get_user_email_from_tags("test-user", tags, is_debug=False)

        assert result == "user@example.com"

    def test_get_email_from_tags_no_email_tag(self, mocker):
        """Test when no email tag is present."""
        mocker.patch("mailers.EMAIL_TAG", "Email")
        mock_log_debug = mocker.patch("mailers.LOG.debug")
        tags = {
            "Tags": [
                {"Key": "Name", "Value": "test-user"},
                {"Key": "Department", "Value": "IT"},
            ],
        }

        result = get_user_email_from_tags("test-user", tags, is_debug=False)

        assert result is None
        mock_log_debug.assert_called_once_with(
            "No email found for user %s",
            "test-user",
        )

    def test_get_email_from_tags_empty_tags(self, mocker):
        """Test when tags list is empty."""
        mocker.patch("mailers.EMAIL_TAG", "Email")
        mock_log_debug = mocker.patch("mailers.LOG.debug")
        tags = {"Tags": []}

        result = get_user_email_from_tags("test-user", tags, is_debug=False)

        assert result is None
        mock_log_debug.assert_called_once()

    def test_get_email_from_tags_invalid_email(self, mocker):
        """Test when email tag has invalid email."""
        mocker.patch("mailers.EMAIL_TAG", "email")
        mock_log_invalid = mocker.patch("mailers.log_invalid_email")
        tags = {
            "Tags": [
                {"Key": "email", "Value": "not-an-email"},
            ],
        }

        result = get_user_email_from_tags("test-user", tags, is_debug=False)

        assert result is None
        mock_log_invalid.assert_called_once_with("user (test-user)", "not-an-email")

    def test_get_email_from_tags_debug_mode(self, mocker):
        """Test that debug mode returns None even with valid email."""
        mocker.patch("mailers.EMAIL_TAG", "email")
        mock_log_debug = mocker.patch("mailers.LOG.debug")
        tags = {
            "Tags": [
                {"Key": "email", "Value": "user@example.com"},
            ],
        }

        result = get_user_email_from_tags("test-user", tags, is_debug=True)

        assert result is None
        assert any(
            call[0][0] == "Debug Mode: Found user email %s"
            for call in mock_log_debug.call_args_list
        )


class TestSendEmail:
    """Tests for send_email function."""

    def test_send_email_success(self, mocker):
        """Test successful email sending."""
        mock_ses_client = mocker.MagicMock()
        mock_ses_client.send_templated_email.return_value = {"MessageId": "msg-123"}

        template_data = {"key": "value"}
        email_targets = ["admin@example.com"]

        result = send_email(
            mock_ses_client,
            "TestTemplate",
            template_data,
            email_targets,
        )

        assert result["MessageId"] == "msg-123"
        mock_ses_client.send_templated_email.assert_called_once_with(
            Source=mocker.ANY,
            Destination={"ToAddresses": email_targets},
            Template="TestTemplate",
            TemplateData=json.dumps(template_data),
        )

    def test_send_email_multiple_recipients(self, mocker):
        """Test sending email to multiple recipients."""
        mock_ses_client = mocker.MagicMock()
        mock_ses_client.send_templated_email.return_value = {"MessageId": "msg-456"}

        template_data = {"action": "delete"}
        email_targets = ["admin@example.com", "manager@example.com"]

        result = send_email(
            mock_ses_client,
            "UserTemplate",
            template_data,
            email_targets,
        )

        assert result["MessageId"] == "msg-456"
        call_args = mock_ses_client.send_templated_email.call_args
        assert call_args[1]["Destination"]["ToAddresses"] == email_targets


class TestGetToAddresses:
    """Tests for get_to_addresses function."""

    def test_get_to_addresses_with_valid_admin(self, mocker):
        """Test getting addresses with valid admin email."""
        mocker.patch("mailers.ADMIN_EMAIL", "admin@example.com")

        result = get_to_addresses([], is_debug=False)

        assert "admin@example.com" in result

    def test_get_to_addresses_with_invalid_admin(self, mocker):
        """Test getting addresses with invalid admin email."""
        mocker.patch("mailers.ADMIN_EMAIL", "invalid-email")
        mock_log_error = mocker.patch("mailers.LOG.error")

        result = get_to_addresses([], is_debug=False)

        assert "invalid-email" not in result
        mock_log_error.assert_called_once()

    def test_get_to_addresses_with_event_targets(self, mocker):
        """Test getting addresses with event email targets."""
        mocker.patch("mailers.ADMIN_EMAIL", "admin@example.com")

        result = get_to_addresses(
            ["user1@example.com", "user2@example.com"],
            is_debug=False,
        )

        assert "admin@example.com" in result
        assert "user1@example.com" in result
        assert "user2@example.com" in result

    def test_get_to_addresses_debug_mode(self, mocker):
        """Test that debug mode excludes event targets."""
        mocker.patch("mailers.ADMIN_EMAIL", "admin@example.com")
        mocker.patch("mailers.LOG.debug")

        result = get_to_addresses(
            ["user1@example.com", "user2@example.com"],
            is_debug=True,
        )

        assert "admin@example.com" in result
        assert "user1@example.com" not in result
        assert "user2@example.com" not in result


class TestGetEventEmailList:
    """Tests for get_event_email_list function."""

    def test_get_event_email_list_all_valid(self):
        """Test getting event email list with all valid emails."""
        email_targets = ["user1@example.com", "user2@example.com"]

        result = get_event_email_list(email_targets, is_debug=False)

        assert result == email_targets

    def test_get_event_email_list_with_invalid(self, mocker):
        """Test getting event email list with some invalid emails."""
        mock_log_error = mocker.patch("mailers.LOG.error")
        email_targets = ["user1@example.com", "invalid", "user2@example.com"]

        result = get_event_email_list(email_targets, is_debug=False)

        assert len(result) == 2
        assert "user1@example.com" in result
        assert "user2@example.com" in result
        assert "invalid" not in result
        mock_log_error.assert_called_once()

    def test_get_event_email_list_debug_mode(self, mocker):
        """Test that debug mode returns empty list."""
        mock_log_debug = mocker.patch("mailers.LOG.debug")
        email_targets = ["user1@example.com", "user2@example.com"]

        result = get_event_email_list(email_targets, is_debug=True)

        assert not result
        mock_log_debug.assert_called_once()

    def test_get_event_email_list_debug_mode_empty_list(self, mocker):
        """Test debug mode with empty input list."""
        mock_log_debug = mocker.patch("mailers.LOG.debug")
        email_targets = []

        result = get_event_email_list(email_targets, is_debug=True)

        assert not result
        mock_log_debug.assert_not_called()


class TestOptionalEmailTemplateData:
    """Tests for optional_email_template_data function."""

    def test_optional_template_data_armed_no_banner(self, mocker):
        """Test template data when armed with no banner."""
        mocker.patch("mailers.EMAIL_BANNER_MSG", "")

        result = optional_email_template_data(armed=True)

        assert not result

    def test_optional_template_data_unarmed_no_banner(self, mocker):
        """Test template data when not armed with no banner."""
        mocker.patch("mailers.EMAIL_BANNER_MSG", "")

        result = optional_email_template_data(armed=False)

        assert result == {"unarmed": True}

    def test_optional_template_data_with_banner(self, mocker):
        """Test template data with banner message."""
        mocker.patch("mailers.EMAIL_BANNER_MSG", "Test Banner")
        mocker.patch("mailers.EMAIL_BANNER_MSG_COLOR", "#FF0000")

        result = optional_email_template_data(armed=True)

        assert result["email_banner_msg"] == "Test Banner"
        assert result["email_banner_msg_color"] == "#FF0000"

    def test_optional_template_data_with_exempt_groups(self, mocker):
        """Test template data with exempt groups."""
        mocker.patch("mailers.EMAIL_BANNER_MSG", "")

        result = optional_email_template_data(
            armed=True,
            exempt_groups="admins, operators",
        )

        assert result["exempt_groups"] == "admins, operators"

    def test_optional_template_data_all_options(self, mocker):
        """Test template data with all options enabled."""
        mocker.patch("mailers.EMAIL_BANNER_MSG", "Warning")
        mocker.patch("mailers.EMAIL_BANNER_MSG_COLOR", "#FFAA00")

        result = optional_email_template_data(
            armed=False,
            exempt_groups="admin-group",
        )

        assert result["email_banner_msg"] == "Warning"
        assert result["email_banner_msg_color"] == "#FFAA00"
        assert result["unarmed"] is True
        assert result["exempt_groups"] == "admin-group"


class TestAdminMailer:
    """Tests for AdminMailer class."""

    def test_admin_mailer_init(self, mocker):
        """Test AdminMailer initialization."""
        mocker.patch("mailers.AWSClientManager")
        email_targets = ["admin@example.com"]
        template_data = {"key": "value"}

        mailer = AdminMailer(email_targets, template_data, is_debug=True)

        assert mailer.email_targets == email_targets
        assert mailer.template_data == template_data
        assert mailer.is_debug is True

    def test_admin_mailer_mail_success(self, mocker):
        """Test successful admin email sending."""
        mock_aws = mocker.MagicMock()
        mock_aws.ses.send_templated_email.return_value = {"MessageId": "msg-123"}
        mocker.patch("mailers.AWSClientManager", return_value=mock_aws)
        mocker.patch("mailers.EMAIL_ADMIN_REPORT_ENABLED", new=True)
        mocker.patch("mailers.ADMIN_EMAIL", "admin@example.com")
        mock_log_info = mocker.patch("mailers.LOG.info")

        email_targets = ["target@example.com"]
        template_data = {"key": "value"}
        mailer = AdminMailer(email_targets, template_data, is_debug=False)

        mailer.mail()

        mock_log_info.assert_called()
        assert "msg-123" in str(mock_log_info.call_args)

    def test_admin_mailer_mail_disabled(self, mocker):
        """Test admin email when disabled."""
        mock_aws = mocker.MagicMock()
        mocker.patch("mailers.AWSClientManager", return_value=mock_aws)
        mocker.patch("mailers.EMAIL_ADMIN_REPORT_ENABLED", new=False)
        mock_log_info = mocker.patch("mailers.LOG.info")

        email_targets = ["admin@example.com"]
        template_data = {"key": "value"}
        mailer = AdminMailer(email_targets, template_data)

        mailer.mail()

        mock_log_info.assert_called_with("Admin Email not enabled per setting")
        mock_aws.ses.send_templated_email.assert_not_called()

    def test_admin_mailer_mail_empty_addresses(self, mocker):
        """Test admin email with empty address list."""
        mock_aws = mocker.MagicMock()
        mocker.patch("mailers.AWSClientManager", return_value=mock_aws)
        mocker.patch("mailers.EMAIL_ADMIN_REPORT_ENABLED", new=True)
        mocker.patch("mailers.ADMIN_EMAIL", "invalid-email")
        mock_log_error = mocker.patch("mailers.LOG.error")

        email_targets = []
        template_data = {"key": "value"}
        mailer = AdminMailer(email_targets, template_data)

        mailer.mail()

        assert any("empty" in str(call) for call in mock_log_error.call_args_list)
        mock_aws.ses.send_templated_email.assert_not_called()

    def test_admin_email_addresses(self, mocker):
        """Test admin_email_addresses method."""
        mocker.patch("mailers.AWSClientManager")
        mocker.patch("mailers.ADMIN_EMAIL", "admin@example.com")

        email_targets = ["target@example.com"]
        mailer = AdminMailer(email_targets, {}, is_debug=False)

        result = mailer.admin_email_addresses()

        assert "admin@example.com" in result
        assert "target@example.com" in result


class TestUserMailer:
    """Tests for UserMailer class."""

    def test_user_mailer_init(self, mocker):
        """Test UserMailer initialization."""
        mocker.patch("mailers.AWSClientManager")
        email_targets = ["admin@example.com"]
        user_email = "user@example.com"
        template_data = {"action": "delete"}

        mailer = UserMailer(email_targets, user_email, template_data, is_debug=False)

        assert mailer.email_targets == email_targets
        assert mailer.user_email == user_email
        assert mailer.template_data == template_data
        assert mailer.is_debug is False

    def test_user_mailer_mail_success(self, mocker):
        """Test successful user email sending."""
        mock_aws = mocker.MagicMock()
        mock_aws.ses.send_templated_email.return_value = {"MessageId": "msg-456"}
        mocker.patch("mailers.AWSClientManager", return_value=mock_aws)
        mocker.patch("mailers.ADMIN_EMAIL", "admin@example.com")
        mock_log_info = mocker.patch("mailers.LOG.info")

        email_targets = []
        user_email = "user@example.com"
        template_data = {"action": "delete"}
        mailer = UserMailer(email_targets, user_email, template_data, is_debug=False)

        mailer.mail()

        mock_log_info.assert_called()
        assert "msg-456" in str(mock_log_info.call_args)

    def test_user_mailer_mail_empty_addresses(self, mocker):
        """Test user email with empty address list."""
        mock_aws = mocker.MagicMock()
        mocker.patch("mailers.AWSClientManager", return_value=mock_aws)
        mocker.patch("mailers.ADMIN_EMAIL", "invalid-email")
        mock_log_error = mocker.patch("mailers.LOG.error")

        email_targets = []
        user_email = None
        template_data = {"action": "delete"}
        mailer = UserMailer(email_targets, user_email, template_data)

        mailer.mail()

        mock_log_error.assert_called_with("User email list is empty, no emails sent")
        mock_aws.ses.send_templated_email.assert_not_called()

    def test_user_to_addresses_with_user_email(self, mocker):
        """Test user_to_addresses includes user email."""
        mocker.patch("mailers.AWSClientManager")
        mocker.patch("mailers.ADMIN_EMAIL", "admin@example.com")

        email_targets = ["target@example.com"]
        user_email = "user@example.com"
        mailer = UserMailer(email_targets, user_email, {}, is_debug=False)

        result = mailer.user_to_addresses()

        assert "admin@example.com" in result
        assert "target@example.com" in result
        assert "user@example.com" in result

    def test_user_to_addresses_without_user_email(self, mocker):
        """Test user_to_addresses without user email."""
        mocker.patch("mailers.AWSClientManager")
        mocker.patch("mailers.ADMIN_EMAIL", "admin@example.com")

        email_targets = ["target@example.com"]
        user_email = None
        mailer = UserMailer(email_targets, user_email, {}, is_debug=False)

        result = mailer.user_to_addresses()

        assert "admin@example.com" in result
        assert "target@example.com" in result
        assert len(result) == 2

    def test_user_to_addresses_debug_mode(self, mocker):
        """Test user_to_addresses in debug mode."""
        mocker.patch("mailers.AWSClientManager")
        mocker.patch("mailers.ADMIN_EMAIL", "admin@example.com")
        mocker.patch("mailers.LOG.debug")

        email_targets = ["target@example.com"]
        user_email = "user@example.com"
        mailer = UserMailer(email_targets, user_email, {}, is_debug=True)

        result = mailer.user_to_addresses()

        assert "admin@example.com" in result
        assert "user@example.com" in result
        assert "target@example.com" not in result
