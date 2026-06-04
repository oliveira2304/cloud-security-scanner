"""
aws_client.py — Thin wrapper around boto3 sessions.

Why this exists:
  - Centralizes session/credential setup so checks never call boto3 directly.
  - Easy to swap in a mock session during tests (just pass a different session object).
  - Handles profile and region selection in one place.

How to extend:
  - Add assume_role() if you want to support cross-account scanning.
  - Add pagination helpers if many checks need them.
"""

import boto3
from botocore.exceptions import NoCredentialsError, ProfileNotFound


class AWSClient:
    def __init__(self, profile: str | None = None, region: str = "us-east-1"):
        self.profile = profile
        self.region = region
        self._session = self._create_session()

    def _create_session(self) -> boto3.Session:
        try:
            session = boto3.Session(
                profile_name=self.profile,
                region_name=self.region,
            )
            # Validate credentials early — fail fast rather than during a check
            session.client("sts").get_caller_identity()
            return session
        except ProfileNotFound:
            raise SystemExit(f"[error] AWS profile '{self.profile}' not found.")
        except NoCredentialsError:
            raise SystemExit("[error] No AWS credentials found. Run 'aws configure'.")

    def get_client(self, service: str):
        """Return a boto3 client for the given service."""
        return self._session.client(service, region_name=self.region)

    def get_resource(self, service: str):
        """Return a boto3 resource for the given service (higher-level API)."""
        return self._session.resource(service, region_name=self.region)

    @property
    def account_id(self) -> str:
        return self._session.client("sts").get_caller_identity()["Account"]
