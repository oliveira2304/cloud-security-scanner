"""
test_integration.py — Integration tests for the full run() orchestration.

Sprint 1 tests called _check_* private functions directly.
These tests call run(AWSClient) — the full public interface — which tests:
  - REGISTRY wiring (a missing import in __init__.py would fail here)
  - run() iterates resources correctly
  - run() passes ClientError to client.record_error() when needed
  - The AWSClient session works end-to-end with moto

Each test creates an AWSClient connected to moto's fake environment,
sets up the specific misconfiguration, and asserts on the result of run().
"""

import json
import boto3
import pytest
from moto import mock_aws

from cloudscan.aws_client import AWSClient
from cloudscan.checks import REGISTRY, s3, iam, ec2, logging_checks
from cloudscan.models import Severity


# ── REGISTRY ──────────────────────────────────────────────────────────────────

def test_registry_contains_all_expected_services():
    assert "s3" in REGISTRY
    assert "iam" in REGISTRY
    assert "ec2" in REGISTRY
    assert "rds" in REGISTRY
    assert "lambda" in REGISTRY
    assert "logging" in REGISTRY


def test_registry_values_are_callable():
    for name, fn in REGISTRY.items():
        assert callable(fn), f"REGISTRY['{name}'] is not callable"


# ── S3 integration ────────────────────────────────────────────────────────────

@mock_aws
def test_s3_run_detects_public_bucket():
    _setup_boto3()
    boto3.client("s3", region_name="us-east-1").create_bucket(Bucket="public-bucket")
    # No public access block = vulnerable

    client = AWSClient(profile=None, region="us-east-1")
    findings = s3.run(client)

    ids = {f.id for f in findings}
    assert "S3_PUBLIC_ACCESS_BLOCK_MISSING" in ids


@mock_aws
def test_s3_run_detects_unencrypted_bucket():
    _setup_boto3()
    boto3.client("s3", region_name="us-east-1").create_bucket(Bucket="no-enc-bucket")

    client = AWSClient(profile=None, region="us-east-1")
    findings = s3.run(client)

    ids = {f.id for f in findings}
    assert "S3_ENCRYPTION_DISABLED" in ids


@mock_aws
def test_s3_run_returns_no_findings_for_secure_bucket():
    _setup_boto3()
    s3c = boto3.client("s3", region_name="us-east-1")
    s3c.create_bucket(Bucket="secure-bucket")
    s3c.put_public_access_block(
        Bucket="secure-bucket",
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True, "IgnorePublicAcls": True,
            "BlockPublicPolicy": True, "RestrictPublicBuckets": True,
        },
    )
    s3c.put_bucket_encryption(
        Bucket="secure-bucket",
        ServerSideEncryptionConfiguration={
            "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]
        },
    )
    s3c.put_bucket_versioning(
        Bucket="secure-bucket",
        VersioningConfiguration={"Status": "Enabled"},
    )

    client = AWSClient(profile=None, region="us-east-1")
    findings = s3.run(client)

    assert findings == [], f"Expected no findings, got: {[f.id for f in findings]}"


@mock_aws
def test_s3_run_no_buckets_returns_empty():
    _setup_boto3()
    client = AWSClient(profile=None, region="us-east-1")
    findings = s3.run(client)
    assert findings == []


# ── IAM integration ───────────────────────────────────────────────────────────

@mock_aws
def test_iam_run_detects_root_no_mfa():
    """moto returns AccountMFAEnabled=0 by default — root has no MFA."""
    _setup_boto3()
    client = AWSClient(profile=None, region="us-east-1")
    findings = iam.run(client)

    ids = {f.id for f in findings}
    assert "IAM_ROOT_NO_MFA" in ids


@mock_aws
def test_iam_run_detects_user_without_mfa():
    _setup_boto3()
    boto3.client("iam", region_name="us-east-1").create_user(UserName="alice")

    client = AWSClient(profile=None, region="us-east-1")
    findings = iam.run(client)

    user_findings = [f for f in findings if f.id == "IAM_USER_NO_MFA" and f.resource == "alice"]
    assert len(user_findings) == 1


@mock_aws
def test_iam_run_detects_wildcard_policy():
    _setup_boto3()
    boto3.client("iam", region_name="us-east-1").create_policy(
        PolicyName="DangerousPolicy",
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
        }),
    )

    client = AWSClient(profile=None, region="us-east-1")
    findings = iam.run(client)

    ids = {f.id for f in findings}
    assert "IAM_POLICY_WILDCARD_ADMIN" in ids


# ── EC2 integration ───────────────────────────────────────────────────────────

@mock_aws
def test_ec2_run_detects_ssh_open_sg():
    _setup_boto3()
    ec2c = boto3.client("ec2", region_name="us-east-1")
    sg = ec2c.create_security_group(GroupName="ssh-open", Description="test")
    ec2c.authorize_security_group_ingress(
        GroupId=sg["GroupId"],
        IpPermissions=[{
            "IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
            "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
        }],
    )

    client = AWSClient(profile=None, region="us-east-1")
    findings = ec2.run(client)

    ids = {f.id for f in findings}
    assert "EC2_SG_SSH_OPEN" in ids


@mock_aws
def test_ec2_run_no_findings_for_clean_sg():
    _setup_boto3()
    ec2c = boto3.client("ec2", region_name="us-east-1")
    sg = ec2c.create_security_group(GroupName="clean-sg", Description="test")
    ec2c.authorize_security_group_ingress(
        GroupId=sg["GroupId"],
        IpPermissions=[{
            "IpProtocol": "tcp", "FromPort": 443, "ToPort": 443,
            "IpRanges": [{"CidrIp": "0.0.0.0/0"}],  # HTTPS is fine
        }],
    )

    client = AWSClient(profile=None, region="us-east-1")
    findings = ec2.run(client)
    assert findings == []


# ── Compliance field ──────────────────────────────────────────────────────────

@mock_aws
def test_findings_from_run_have_compliance_populated():
    """
    Verify that findings produced by run() carry compliance data.
    This would catch a regression where get_compliance() import was removed.
    """
    _setup_boto3()
    boto3.client("s3", region_name="us-east-1").create_bucket(Bucket="test-bucket")

    client = AWSClient(profile=None, region="us-east-1")
    findings = s3.run(client)

    public_access_findings = [f for f in findings if "PUBLIC_ACCESS" in f.id]
    assert public_access_findings, "Expected at least one public access finding"

    for f in public_access_findings:
        assert f.compliance, f"Finding {f.id} has no compliance data"
        assert "CIS_AWS_1.4" in f.compliance, f"Finding {f.id} missing CIS_AWS_1.4 mapping"
        assert f.cis_controls(), f"Finding {f.id} cis_controls() returned empty"


# ── Helpers ───────────────────────────────────────────────────────────────────

def _setup_boto3():
    """
    moto needs at least one boto3 call before AWSClient() so the mock is active.
    Creating a dummy STS client here also avoids a race condition where
    AWSClient._create_session() runs before moto has intercepted STS.
    """
    boto3.client("sts", region_name="us-east-1").get_caller_identity()
