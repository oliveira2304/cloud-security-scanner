"""
test_s3.py — Unit tests for S3 checks.

Each test:
  1. Creates a real-looking fake bucket using moto
  2. Configures it to have a specific misconfiguration (or not)
  3. Calls the check function directly
  4. Asserts on the finding ID and severity

Why we call _check_* functions directly:
  Testing internal functions gives tighter feedback — if a test fails you
  know exactly which check broke. Testing run() only would be coarser.
"""

import boto3
import pytest
from moto import mock_aws

from cloudscan.checks.s3 import _check_encryption, _check_public_access, _check_versioning
from cloudscan.models import Severity


@mock_aws
def test_public_access_block_missing_reports_critical():
    s3 = boto3.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket="test-bucket")
    # Do NOT set any public access block config — this is the vulnerable state

    findings = _check_public_access(s3, "test-bucket")

    assert len(findings) == 1
    assert findings[0].id == "S3_PUBLIC_ACCESS_BLOCK_MISSING"
    assert findings[0].severity == Severity.CRITICAL


@mock_aws
def test_public_access_block_partial_reports_critical():
    s3 = boto3.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket="test-bucket")
    # Only some settings enabled — still vulnerable
    s3.put_public_access_block(
        Bucket="test-bucket",
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": False,   # missing
            "RestrictPublicBuckets": False,  # missing
        },
    )

    findings = _check_public_access(s3, "test-bucket")

    assert len(findings) == 1
    assert findings[0].id == "S3_PUBLIC_ACCESS_BLOCK_DISABLED"
    assert findings[0].severity == Severity.CRITICAL
    assert "BlockPublicPolicy" in findings[0].evidence


@mock_aws
def test_public_access_block_fully_enabled_no_finding():
    s3 = boto3.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket="test-bucket")
    s3.put_public_access_block(
        Bucket="test-bucket",
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        },
    )

    findings = _check_public_access(s3, "test-bucket")

    assert findings == []


@mock_aws
def test_encryption_missing_reports_high():
    s3 = boto3.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket="test-bucket")
    # No encryption configured

    findings = _check_encryption(s3, "test-bucket")

    assert len(findings) == 1
    assert findings[0].id == "S3_ENCRYPTION_DISABLED"
    assert findings[0].severity == Severity.HIGH


@mock_aws
def test_encryption_enabled_no_finding():
    s3 = boto3.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket="test-bucket")
    s3.put_bucket_encryption(
        Bucket="test-bucket",
        ServerSideEncryptionConfiguration={
            "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]
        },
    )

    findings = _check_encryption(s3, "test-bucket")

    assert findings == []


@mock_aws
def test_versioning_disabled_reports_medium():
    s3 = boto3.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket="test-bucket")
    # No versioning configured

    findings = _check_versioning(s3, "test-bucket")

    assert len(findings) == 1
    assert findings[0].id == "S3_VERSIONING_DISABLED"
    assert findings[0].severity == Severity.MEDIUM


@mock_aws
def test_versioning_enabled_no_finding():
    s3 = boto3.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket="test-bucket")
    s3.put_bucket_versioning(
        Bucket="test-bucket",
        VersioningConfiguration={"Status": "Enabled"},
    )

    findings = _check_versioning(s3, "test-bucket")

    assert findings == []
