"""
checks/s3.py — S3 security checks.

Error handling strategy:
  _check_* functions catch only EXPECTED exceptions (e.g. NoSuchPublicAccessBlockConfiguration,
  which is a normal API response meaning "config doesn't exist").

  They do NOT catch ClientError — if AWS returns AccessDenied or any other unexpected
  error, it bubbles up to run(), which records it via client.record_error().

  This means: if a check fails due to missing permissions, it appears in the
  scan summary as a ScanError, not as a silent "no findings".
"""

import logging
from typing import List

from botocore.exceptions import ClientError

from cloudscan.aws_client import AWSClient
from cloudscan.models import Finding, Severity

logger = logging.getLogger(__name__)


def run(client: AWSClient) -> List[Finding]:
    s3 = client.get_client("s3")
    findings: List[Finding] = []

    try:
        response = s3.list_buckets()
    except ClientError as e:
        client.record_error("S3", "list_buckets", "*", e)
        return findings

    for bucket in response.get("Buckets", []):
        name = bucket["Name"]
        logger.debug("Scanning S3 bucket: %s", name)

        for check_fn in (_check_public_access, _check_encryption, _check_versioning):
            try:
                findings.extend(check_fn(s3, name))
            except ClientError as e:
                client.record_error("S3", check_fn.__name__, name, e)

    return findings


def _check_public_access(s3_client, bucket_name: str) -> List[Finding]:
    """Detect if Block Public Access is not fully enabled."""
    try:
        config = s3_client.get_public_access_block(Bucket=bucket_name)
        block = config["PublicAccessBlockConfiguration"]

        all_blocked = all([
            block.get("BlockPublicAcls", False),
            block.get("IgnorePublicAcls", False),
            block.get("BlockPublicPolicy", False),
            block.get("RestrictPublicBuckets", False),
        ])

        if not all_blocked:
            disabled = [k for k, v in block.items() if not v]
            return [Finding(
                id="S3_PUBLIC_ACCESS_BLOCK_DISABLED",
                service="S3",
                resource=bucket_name,
                severity=Severity.CRITICAL,
                title="S3 Block Public Access not fully enabled",
                description=(
                    "The bucket does not have all four Block Public Access settings enabled. "
                    "This may allow public read/write access to objects."
                ),
                recommendation=(
                    "Enable all Block Public Access settings: "
                    "BlockPublicAcls, IgnorePublicAcls, BlockPublicPolicy, RestrictPublicBuckets."
                ),
                evidence=f"Disabled settings: {', '.join(disabled)}",
            )]

    except ClientError as e:
        if e.response["Error"]["Code"] == "NoSuchPublicAccessBlockConfiguration":
            return [Finding(
                id="S3_PUBLIC_ACCESS_BLOCK_MISSING",
                service="S3",
                resource=bucket_name,
                severity=Severity.CRITICAL,
                title="S3 Block Public Access configuration missing",
                description="No Block Public Access configuration exists — the bucket defaults to public.",
                recommendation="Enable S3 Block Public Access at both bucket and account level.",
                evidence="PublicAccessBlockConfiguration: not found",
            )]
        raise  # unexpected error — let run() catch and record it

    return []


def _check_encryption(s3_client, bucket_name: str) -> List[Finding]:
    """Detect if server-side encryption is not configured."""
    try:
        s3_client.get_bucket_encryption(Bucket=bucket_name)
    except ClientError as e:
        if e.response["Error"]["Code"] == "ServerSideEncryptionConfigurationNotFoundError":
            return [Finding(
                id="S3_ENCRYPTION_DISABLED",
                service="S3",
                resource=bucket_name,
                severity=Severity.HIGH,
                title="S3 bucket encryption not enabled",
                description="The bucket has no default server-side encryption configured.",
                recommendation=(
                    "Enable default encryption using SSE-S3 (AES-256) or SSE-KMS. "
                    "Prefer SSE-KMS for audit trail and key rotation."
                ),
                evidence="GetBucketEncryption: ServerSideEncryptionConfigurationNotFoundError",
            )]
        raise  # unexpected error — let run() catch and record it

    return []


def _check_versioning(s3_client, bucket_name: str) -> List[Finding]:
    """Detect if versioning is not enabled."""
    response = s3_client.get_bucket_versioning(Bucket=bucket_name)
    status = response.get("Status", "")

    if status != "Enabled":
        return [Finding(
            id="S3_VERSIONING_DISABLED",
            service="S3",
            resource=bucket_name,
            severity=Severity.MEDIUM,
            title="S3 bucket versioning not enabled",
            description=(
                "Without versioning, deleted or overwritten objects cannot be recovered. "
                "This increases ransomware impact."
            ),
            recommendation="Enable versioning. Consider MFA Delete for critical buckets.",
            evidence=f"VersioningConfiguration.Status: '{status or 'not set'}'",
        )]

    return []
