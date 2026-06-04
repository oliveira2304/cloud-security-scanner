"""
aws_client.py — Thin wrapper around boto3 sessions.

Changes in Sprint 1:
  - `errors` list: checks append ScanError here instead of silently swallowing exceptions.
  - `account_id` is now cached — the original implementation called STS on every property
    access, meaning a 10-service scan triggered 10 unnecessary API calls.
  - `_create_session` still validates credentials at startup (fail fast), but reuses the
    identity result rather than discarding it.
"""

import logging

import boto3
from botocore.exceptions import ClientError, NoCredentialsError, ProfileNotFound

from cloudscan.models import ScanError

logger = logging.getLogger(__name__)


class AWSClient:
    def __init__(self, profile: str | None = None, region: str = "us-east-1"):
        self.profile = profile
        self.region = region
        self.errors: list[ScanError] = []
        self._session, self._account_id = self._create_session()

    def _create_session(self) -> tuple[boto3.Session, str]:
        try:
            session = boto3.Session(
                profile_name=self.profile,
                region_name=self.region,
            )
            # Validate credentials immediately and cache the account ID.
            identity = session.client("sts").get_caller_identity()
            account_id = identity["Account"]
            logger.debug("Authenticated as %s (account %s)", identity.get("Arn"), account_id)
            return session, account_id

        except ProfileNotFound:
            raise SystemExit(f"[error] AWS profile '{self.profile}' not found.")
        except NoCredentialsError:
            raise SystemExit("[error] No AWS credentials found. Run 'aws configure'.")
        except ClientError as e:
            raise SystemExit(f"[error] Could not authenticate with AWS: {e}")

    def get_client(self, service: str):
        """Return a boto3 client for the given service."""
        return self._session.client(service, region_name=self.region)

    def get_resource(self, service: str):
        """Return a boto3 resource for the given service."""
        return self._session.resource(service, region_name=self.region)

    def record_error(
        self,
        service: str,
        check: str,
        resource: str,
        error: ClientError,
    ) -> None:
        """
        Classify a ClientError and append it to self.errors.

        Called by check run() functions when an API call fails.
        This ensures errors are always visible — never swallowed.
        """
        code = error.response["Error"]["Code"]
        message = error.response["Error"]["Message"]

        if code in ("AccessDenied", "AccessDeniedException", "AuthFailure"):
            error_type = "ACCESS_DENIED"
            logger.warning(
                "ACCESS DENIED — %s/%s on resource '%s'. "
                "Add the required IAM permission to the scanning role.",
                service, check, resource,
            )
        else:
            error_type = "API_ERROR"
            logger.warning("API error in %s/%s on '%s': [%s] %s", service, check, resource, code, message)

        self.errors.append(ScanError(
            service=service,
            check=check,
            resource=resource,
            error_type=error_type,
            message=f"[{code}] {message}",
        ))

    @property
    def account_id(self) -> str:
        return self._account_id
