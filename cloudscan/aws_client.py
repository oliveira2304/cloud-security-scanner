"""
aws_client.py — Thin wrapper around boto3 sessions.

Sprint 3 additions:
  - for_region(region): returns a lightweight AWSClient for a different region,
    reusing the same session (no extra STS call). Used by multi-region scanning.
  - list_enabled_regions(service): returns all regions where a service is available,
    filtered to opt-in regions the account has enabled.
"""

import logging
from typing import Optional

import boto3
from botocore.exceptions import ClientError, NoCredentialsError, ProfileNotFound

from cloudscan.models import ScanError

logger = logging.getLogger(__name__)


class AWSClient:
    def __init__(self, profile: Optional[str] = None, region: str = "us-east-1"):
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

    # ── Region helpers ────────────────────────────────────────────────────────

    def for_region(self, region: str) -> "AWSClient":
        """
        Return an AWSClient for a different region, reusing the same session.

        This avoids an extra STS call per region — we already validated
        credentials in __init__. The errors list is shared so all regional
        scan errors are aggregated in one place.
        """
        regional = AWSClient.__new__(AWSClient)
        regional.profile = self.profile
        regional.region = region
        regional.errors = self.errors          # shared — all regions, one error list
        regional._session = self._session
        regional._account_id = self._account_id
        return regional

    def list_enabled_regions(self, service: str = "ec2") -> list[str]:
        """
        Return all regions where `service` is available and the account has opted in.

        Uses ec2:DescribeRegions which is cheaper than listing per-service endpoints.
        Filters out disabled opt-in regions (e.g. ap-southeast-3 if not activated).
        """
        try:
            ec2 = self._session.client("ec2", region_name="us-east-1")
            response = ec2.describe_regions(
                Filters=[{"Name": "opt-in-status", "Values": ["opt-in-not-required", "opted-in"]}]
            )
            return [r["RegionName"] for r in response["Regions"]]
        except ClientError as e:
            logger.warning("Could not list regions: %s. Falling back to current region.", e)
            return [self.region]

    # ── boto3 accessors ───────────────────────────────────────────────────────

    def get_client(self, service: str):
        return self._session.client(service, region_name=self.region)

    def get_resource(self, service: str):
        return self._session.resource(service, region_name=self.region)

    # ── Error recording ───────────────────────────────────────────────────────

    def record_error(
        self,
        service: str,
        check: str,
        resource: str,
        error: ClientError,
    ) -> None:
        """Classify a ClientError and append it to self.errors."""
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
            logger.warning(
                "API error in %s/%s on '%s': [%s] %s",
                service, check, resource, code, message,
            )

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
