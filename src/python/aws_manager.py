"""
AWS client manager module.

This module provides a singleton-based AWS client manager for managing
AWS service clients (S3, SES) using boto3.

"""

from typing import ClassVar

import boto3


class Singleton(type):
    """
    Metaclass for implementing the Singleton pattern.

    Ensures that only one instance of a class exists by caching instances.

    """

    _instances: ClassVar[dict] = {}

    def __call__(cls, *args, **kwargs):
        """
        Create or return the singleton instance.

        Parameters
        ----------
        *args
            Positional arguments to pass to the class constructor.
        **kwargs
            Keyword arguments to pass to the class constructor.

        Returns
        -------
        object
            The singleton instance of the class.

        """
        if cls not in cls._instances:
            cls._instances[cls] = super().__call__(*args, **kwargs)
        return cls._instances[cls]


class AWSClientManager(metaclass=Singleton):
    """
    Singleton manager for AWS service clients.

    Provides lazy-loaded AWS service clients (S3, SES) using a shared boto3 session.

    Attributes
    ----------
    session : boto3.Session
        The boto3 session used for creating service clients.

    """

    def __init__(self, session=None):
        """
        Initialize the AWS Client Manager.

        Parameters
        ----------
        session : boto3.Session, optional
            Boto3 session to use. If None, creates a new session.

        """
        # Initializing the session here is safe because we mock it in conftest
        self.session = session or boto3.Session()
        self._s3 = None
        self._ses = None

    @property
    def s3(self):
        """
        Get or create the S3 client.

        Returns
        -------
        boto3.client
            The S3 service client.

        """
        if self._s3 is None:
            self._s3 = self.session.client("s3")
        return self._s3

    @property
    def ses(self):
        """
        Get or create the SES client.

        Returns
        -------
        boto3.client
            The SES service client.

        """
        if self._ses is None:
            self._ses = self.session.client("ses")
        return self._ses
