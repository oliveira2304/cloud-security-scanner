"""
checks/s3.py — S3 security checks.

What this file does:
  Iterates all S3 buckets in the account and runs three checks:
    1. Public bucket (Block Public Access disabled)
    2. Encryption not enabled at rest (SSE)
    3. Versioning disabled

Why structured this way:
  Each check is a private function (_check_*) that takes a bucket name and client.
  run() orchestrates them. This makes unit testing each check trivial — you don't
  need a full AWS environment, just a mock client.

How to test:
  See tests/test_s3.py — uses moto to mock AWS without real credentials.

How to improve:
  - Add bucket policy analysis (detect overly permissive policies)
  - Add object-level logging check (S3 access logs enabled)
  - Add lifecycle policy check
"""

from typing import List

from cloudscan.aws_client import AWSClient
from cloudscan.models import Finding, Severity


def run(client: AWSClient) -> List[Finding]:
    s3 = client.get_client("s3")
    findings: List[Finding] = []

    response = s3.list_buckets()
    buckets = response.get("Buckets", [])

    for bucket in buckets:
        name = bucket["Name"]
        findings.extend(_check_public_access(s3, name))
        findings.extend(_check_encryption(s3, name))
        findings.extend(_check_versioning(s3, name))

    return findings


def _check_public_access(s3_client, bucket_name: str) -> List[Finding]:
    """Detect if Block Public Access is fully disabled on the bucket."""
    try:
        config = s3_client.get_public_access_block(Bucket=bucket_name)
        block = config["PublicAccessBlockConfiguration"]

        # All four settings must be True to be considered safe
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
                    "Enable all Block Public Access settings on the bucket and at account level: "
                    "BlockPublicAcls, IgnorePublicAcls, BlockPublicPolicy, RestrictPublicBuckets."
                ),
                evidence=f"Disabled settings: {', '.join(disabled)}",
            )]

    except s3_client.exceptions.NoSuchPublicAccessBlockConfiguration:
        # No configuration at all = fully public by default
        return [Finding(
            id="S3_PUBLIC_ACCESS_BLOCK_MISSING",
            service="S3",
            resource=bucket_name,
            severity=Severity.CRITICAL,
            title="S3 Block Public Access configuration missing",
            description="The bucket has no Block Public Access configuration, which defaults to public.",
            recommendation="Enable S3 Block Public Access at both bucket and account level.",
            evidence="PublicAccessBlockConfiguration: not found",
        )]
    except Exception:
        pass

    return []


def _check_encryption(s3_client, bucket_name: str) -> List[Finding]:
    """Detect if server-side encryption is not configured."""
    try:
        s3_client.get_bucket_encryption(Bucket=bucket_name)
    except s3_client.exceptions.ServerSideEncryptionConfigurationNotFoundError:
        return [Finding(
            id="S3_ENCRYPTION_DISABLED",
            service="S3",
            resource=bucket_name,
            severity=Severity.HIGH,
            title="S3 bucket encryption not enabled",
            description="The bucket does not have default server-side encryption configured.",
            recommendation=(
                "Enable default encryption using SSE-S3 (AES-256) or SSE-KMS. "
                "Prefer SSE-KMS for audit trail and key rotation capabilities."
            ),
            evidence="GetBucketEncryption returned ServerSideEncryptionConfigurationNotFoundError",
        )]
    except Exception:
        pass

    return []


def _check_versioning(s3_client, bucket_name: str) -> List[Finding]:
    """Detect if versioning is not enabled (useful for ransomware recovery)."""
    try:
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
                    "Versioning is not enabled. Without versioning, deleted or overwritten "
                    "objects cannot be recovered — this increases ransomware impact."
                ),
                recommendation="Enable versioning on the bucket. Consider MFA Delete for critical buckets.",
                evidence=f"VersioningConfiguration.Status: '{status or 'not set'}'",
            )]
    except Exception:
        pass

    return []
