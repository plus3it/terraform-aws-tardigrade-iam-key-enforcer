"""Pytest configuration and shared fixtures."""

import os
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import boto3
import pytest

# Add src/python to Python path so imports work
src_python = Path(__file__).parent.parent.parent / "src" / "python"
sys.path.insert(0, str(src_python))

# Set fake AWS credentials to prevent any real AWS calls
os.environ["AWS_ACCESS_KEY_ID"] = "testing"
os.environ["AWS_SECRET_ACCESS_KEY"] = "testing"
os.environ["AWS_SECURITY_TOKEN"] = "testing"
os.environ["AWS_SESSION_TOKEN"] = "testing"
os.environ["AWS_DEFAULT_REGION"] = "us-east-1"


@pytest.fixture(scope="session", autouse=True)
def mock_boto3_globally():
    """
    Mock boto3 globally before any imports to prevent real AWS calls.

    This fixture runs automatically at session start and mocks boto3.Session
    so that when aws_manager is imported, it won't make real AWS calls.

    Yields
    ------
    dict
        Dictionary containing the mocked boto3 session and client.

    """
    # Create mock session that returns mock clients
    mock_session = MagicMock()
    mock_s3_client = MagicMock()
    mock_ses_client = MagicMock()

    # Configure session.client to return appropriate mock based on service name
    def get_mock_client(service_name, **_kwargs):
        if service_name == "s3":
            return mock_s3_client
        if service_name == "ses":
            return mock_ses_client
        return MagicMock()

    mock_session.client.side_effect = get_mock_client

    # Patch boto3.Session globally
    with patch.object(boto3, "Session", return_value=mock_session):
        yield {
            "session": mock_session,
            "s3_client": mock_s3_client,
            "ses_client": mock_ses_client,
        }


@pytest.fixture(autouse=True)
def reset_singleton():
    """
    Reset the Singleton instances between tests.

    This ensures each test starts with a fresh AWSClientManager instance.

    """
    # Import here to avoid circular dependency issues
    try:
        from aws_manager import Singleton  # pylint: disable=import-outside-toplevel

        # Clear singleton instances before each test
        Singleton._instances.clear()  # pylint: disable=protected-access
    except ImportError:
        # aws_manager module not needed for all tests
        pass

    yield

    # Clear singleton instances after each test
    try:
        from aws_manager import Singleton  # pylint: disable=import-outside-toplevel

        Singleton._instances.clear()  # pylint: disable=protected-access
    except ImportError:
        # aws_manager module not needed for all tests
        pass


@pytest.fixture
def mock_iam_client():
    """
    Create a mock boto3 IAM client for testing.

    This fixture provides a properly configured mock that simulates
    a boto3 IAM client created from an assumed role session. It includes
    mock methods for all IAM operations used by IamKeyEnforcerReporter.

    Returns
    -------
    MagicMock
        A mock IAM client with pre-configured methods.

    """
    mock_client = MagicMock()

    # Configure delete_access_key to return successfully
    mock_client.delete_access_key.return_value = {}

    # Configure update_access_key to return successfully
    mock_client.update_access_key.return_value = {}

    # Configure list_user_tags to return empty tags by default
    mock_client.list_user_tags.return_value = {"Tags": []}

    return mock_client
