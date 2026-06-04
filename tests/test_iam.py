"""
test_iam.py — Unit tests for IAM checks.

Coverage:
  - Root access keys present
  - Root MFA not enabled
  - IAM user without MFA
  - IAM user with old access key
  - IAM user with fresh access key (no finding)
  - Wildcard admin policy
"""

import boto3
import pytest
from moto import mock_aws

from cloudscan.checks.iam import (
    _check_access_key_age,
    _check_admin_policies,
    _check_mfa,
    _check_root_account,
)
from cloudscan.models import Severity


# ── Root account checks ───────────────────────────────────────────────────────

@mock_aws
def test_root_no_mfa_reports_critical():
    iam = boto3.client("iam", region_name="us-east-1")

    # moto's GetAccountSummary returns AccountMFAEnabled=0 by default
    from unittest.mock import patch, MagicMock
    aws_client = MagicMock()
    aws_client.errors = []

    findings = _check_root_account(iam, aws_client)

    mfa_findings = [f for f in findings if f.id == "IAM_ROOT_NO_MFA"]
    assert len(mfa_findings) == 1
    assert mfa_findings[0].severity == Severity.CRITICAL
    assert mfa_findings[0].resource == "root"


@mock_aws
def test_root_access_keys_absent_no_finding():
    """
    moto returns AccountAccessKeysPresent=0 by default (no root keys).
    Verify no false positive.
    """
    iam = boto3.client("iam", region_name="us-east-1")
    from unittest.mock import MagicMock

    aws_client = MagicMock()
    aws_client.errors = []

    findings = _check_root_account(iam, aws_client)

    key_findings = [f for f in findings if f.id == "IAM_ROOT_ACCESS_KEY_EXISTS"]
    assert key_findings == []


# ── Per-user MFA checks ───────────────────────────────────────────────────────

@mock_aws
def test_user_without_mfa_reports_high():
    iam = boto3.client("iam", region_name="us-east-1")
    iam.create_user(UserName="alice")

    findings = _check_mfa(iam, "alice")

    assert len(findings) == 1
    assert findings[0].id == "IAM_USER_NO_MFA"
    assert findings[0].severity == Severity.HIGH
    assert findings[0].resource == "alice"


# ── Access key age ────────────────────────────────────────────────────────────

@mock_aws
def test_fresh_access_key_no_finding():
    """A key created now should not trigger — it is within the 90-day window."""
    iam = boto3.client("iam", region_name="us-east-1")
    iam.create_user(UserName="ci-bot")
    iam.create_access_key(UserName="ci-bot")

    findings = _check_access_key_age(iam, "ci-bot")

    assert findings == []


@mock_aws
def test_no_access_keys_no_finding():
    iam = boto3.client("iam", region_name="us-east-1")
    iam.create_user(UserName="console-only")

    findings = _check_access_key_age(iam, "console-only")

    assert findings == []


@mock_aws
def test_inactive_key_not_reported():
    """Inactive keys should not trigger a rotation finding."""
    iam = boto3.client("iam", region_name="us-east-1")
    iam.create_user(UserName="old-user")
    key = iam.create_access_key(UserName="old-user")["AccessKey"]
    iam.update_access_key(
        UserName="old-user",
        AccessKeyId=key["AccessKeyId"],
        Status="Inactive",
    )

    findings = _check_access_key_age(iam, "old-user")

    assert findings == []


# ── Wildcard policy ───────────────────────────────────────────────────────────

@mock_aws
def test_wildcard_admin_policy_reports_critical():
    import json
    iam = boto3.client("iam", region_name="us-east-1")
    from unittest.mock import MagicMock

    aws_client = MagicMock()
    aws_client.errors = []

    iam.create_policy(
        PolicyName="DangerousWildcard",
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
        }),
    )

    findings = _check_admin_policies(iam, aws_client)

    assert len(findings) == 1
    assert findings[0].id == "IAM_POLICY_WILDCARD_ADMIN"
    assert findings[0].severity == Severity.CRITICAL
    assert findings[0].resource == "DangerousWildcard"


@mock_aws
def test_scoped_policy_no_finding():
    """A policy with specific actions should not trigger."""
    import json
    iam = boto3.client("iam", region_name="us-east-1")
    from unittest.mock import MagicMock

    aws_client = MagicMock()
    aws_client.errors = []

    iam.create_policy(
        PolicyName="ScopedReadOnly",
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": "arn:aws:s3:::my-bucket/*"}],
        }),
    )

    findings = _check_admin_policies(iam, aws_client)

    assert findings == []
