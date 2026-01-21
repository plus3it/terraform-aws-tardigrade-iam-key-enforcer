"""
Tests for AWS Client Manager.

This module tests the AWSClientManager singleton pattern and its
interactions with AWS services (S3, SES).

"""

import pytest
from aws_manager import AWSClientManager, Singleton  # pylint: disable=import-error


@pytest.fixture(autouse=True)
def clear_singleton():
    """Reset the Singleton and mocks between every test execution."""
    Singleton._instances = {}  # pylint: disable=protected-access


def test_s3_interaction_success(mocker):
    """
    Test successful S3 interaction through AWSClientManager.

    Parameters
    ----------
    mocker
        Pytest-mock mocker fixture.

    """
    # Setup the mock S3 client
    mock_s3 = mocker.MagicMock()
    mock_s3.put_object.return_value = {
        "ETag": '"abc123"',
        "VersionId": "v1",
        "ResponseMetadata": {"HTTPStatusCode": 200},
    }

    # Inject the mock into our Singleton instance
    mocker.patch.object(
        AWSClientManager,
        "s3",
        new_callable=mocker.PropertyMock,
        return_value=mock_s3,
    )

    # Execute logic using AWSClientManager
    aws = AWSClientManager()
    response = aws.s3.put_object(
        Bucket="test-bucket",
        Key="test-key",
        Body=b"test data",
    )

    # Assertions
    assert response["ETag"] == '"abc123"'
    assert response["VersionId"] == "v1"
    assert response["ResponseMetadata"]["HTTPStatusCode"] == 200
    mock_s3.put_object.assert_called_once_with(
        Bucket="test-bucket",
        Key="test-key",
        Body=b"test data",
    )


def test_ses_interaction_success(mocker):
    """
    Test successful SES interaction through AWSClientManager.

    Parameters
    ----------
    mocker
        Pytest-mock mocker fixture.

    """
    mock_ses = mocker.MagicMock()
    mock_ses.send_email.return_value = {"MessageId": "12345"}

    mocker.patch.object(
        AWSClientManager,
        "ses",
        new_callable=mocker.PropertyMock,
        return_value=mock_ses,
    )

    # Execute logic using AWSClientManager
    aws = AWSClientManager()
    res = aws.ses.send_email(Source="test@test.com", Destination={}, Message={})

    # Assertions
    assert res["MessageId"] == "12345"
    mock_ses.send_email.assert_called_once_with(
        Source="test@test.com",
        Destination={},
        Message={},
    )


def test_singleton_pattern():
    """Test that AWSClientManager implements singleton pattern correctly."""
    # Create first instance
    aws1 = AWSClientManager()

    # Create second instance
    aws2 = AWSClientManager()

    # Both should be the same instance
    assert aws1 is aws2


def test_s3_client_lazy_loading(mocker):
    """
    Test that S3 client is lazily loaded on first access.

    Parameters
    ----------
    mocker
        Pytest-mock mocker fixture.

    """
    mock_session = mocker.MagicMock()
    mock_s3_client = mocker.MagicMock()
    mock_session.client.return_value = mock_s3_client

    aws = AWSClientManager(session=mock_session)

    # Client method should not be called yet
    mock_session.client.assert_not_called()

    # Access the s3 property
    _ = aws.s3

    # Now client should be called with "s3"
    mock_session.client.assert_called_once_with("s3")


def test_ses_client_lazy_loading(mocker):
    """
    Test that SES client is lazily loaded on first access.

    Parameters
    ----------
    mocker
        Pytest-mock mocker fixture.

    """
    mock_session = mocker.MagicMock()
    mock_ses_client = mocker.MagicMock()
    mock_session.client.return_value = mock_ses_client

    aws = AWSClientManager(session=mock_session)

    # Client method should not be called yet
    mock_session.client.assert_not_called()

    # Access the ses property
    _ = aws.ses

    # Now client should be called with "ses"
    mock_session.client.assert_called_once_with("ses")
