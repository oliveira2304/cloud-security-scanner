"""
test_rds.py — Unit and integration tests for RDS checks.
"""

import boto3
import pytest
from moto import mock_aws

from cloudscan.checks.rds import (
    _check_public_access,
    _check_encryption,
    _check_deletion_protection,
    _check_multi_az,
    run,
)
from cloudscan.aws_client import AWSClient
from cloudscan.models import Severity


def _make_instance(**overrides) -> dict:
    """Build a minimal RDS instance dict, with safe defaults."""
    base = {
        "DBInstanceIdentifier": "test-db",
        "Engine": "mysql",
        "DBInstanceClass": "db.t3.micro",
        "PubliclyAccessible": False,
        "StorageEncrypted": True,
        "DeletionProtection": True,
        "MultiAZ": True,
        "Endpoint": {"Address": "test-db.example.rds.amazonaws.com", "Port": 3306},
    }
    base.update(overrides)
    return base


# ── Public access ─────────────────────────────────────────────────────────────

def test_public_instance_reports_critical():
    findings = _check_public_access(_make_instance(PubliclyAccessible=True))
    assert len(findings) == 1
    assert findings[0].id == "RDS_INSTANCE_PUBLIC"
    assert findings[0].severity == Severity.CRITICAL


def test_private_instance_no_finding():
    findings = _check_public_access(_make_instance(PubliclyAccessible=False))
    assert findings == []


# ── Encryption ────────────────────────────────────────────────────────────────

def test_unencrypted_instance_reports_high():
    findings = _check_encryption(_make_instance(StorageEncrypted=False))
    assert len(findings) == 1
    assert findings[0].id == "RDS_ENCRYPTION_DISABLED"
    assert findings[0].severity == Severity.HIGH


def test_encrypted_instance_no_finding():
    findings = _check_encryption(_make_instance(StorageEncrypted=True))
    assert findings == []


# ── Deletion protection ───────────────────────────────────────────────────────

def test_no_deletion_protection_reports_medium():
    findings = _check_deletion_protection(_make_instance(DeletionProtection=False))
    assert len(findings) == 1
    assert findings[0].id == "RDS_DELETION_PROTECTION_OFF"
    assert findings[0].severity == Severity.MEDIUM


def test_deletion_protection_enabled_no_finding():
    findings = _check_deletion_protection(_make_instance(DeletionProtection=True))
    assert findings == []


# ── Multi-AZ ──────────────────────────────────────────────────────────────────

def test_single_az_reports_low():
    findings = _check_multi_az(_make_instance(MultiAZ=False))
    assert len(findings) == 1
    assert findings[0].id == "RDS_MULTI_AZ_DISABLED"
    assert findings[0].severity == Severity.LOW


def test_multi_az_no_finding():
    findings = _check_multi_az(_make_instance(MultiAZ=True))
    assert findings == []


# ── Compliance ────────────────────────────────────────────────────────────────

def test_rds_findings_have_compliance():
    for fn, kwargs in [
        (_check_public_access, {"PubliclyAccessible": True}),
        (_check_encryption,    {"StorageEncrypted": False}),
        (_check_deletion_protection, {"DeletionProtection": False}),
        (_check_multi_az,      {"MultiAZ": False}),
    ]:
        findings = fn(_make_instance(**kwargs))
        assert findings, f"{fn.__name__} returned no findings"
        for f in findings:
            assert f.compliance, f"{f.id} has no compliance data"
            assert "CIS_AWS_1.4" in f.compliance


# ── Integration: run() with moto ─────────────────────────────────────────────

@mock_aws
def test_rds_run_no_instances_returns_empty():
    boto3.client("sts", region_name="us-east-1").get_caller_identity()
    client = AWSClient(profile=None, region="us-east-1")
    findings = run(client)
    assert findings == []
    assert client.errors == []
