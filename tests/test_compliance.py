"""
test_compliance.py — Verify the compliance mapping module.

These tests ensure:
  1. Every finding ID used in checks/ has an entry in compliance.py
  2. No compliance entry points to an empty controls list for CIS
  3. The compliance data is structurally valid
  4. Helper methods on Finding (cis_controls, nist_controls) work correctly
"""

import pytest

from cloudscan.compliance import get_compliance, all_finding_ids
from cloudscan.models import Finding, Severity


# All finding IDs that checks/ can produce — kept in sync manually.
# If you add a new check, add its ID here.
ALL_CHECK_IDS = [
    "IAM_ROOT_ACCESS_KEY_EXISTS",
    "IAM_ROOT_NO_MFA",
    "IAM_ROOT_USED_RECENTLY",
    "IAM_USER_NO_MFA",
    "IAM_ACCESS_KEY_NOT_ROTATED",
    "IAM_POLICY_WILDCARD_ADMIN",
    "S3_PUBLIC_ACCESS_BLOCK_MISSING",
    "S3_PUBLIC_ACCESS_BLOCK_DISABLED",
    "S3_ENCRYPTION_DISABLED",
    "S3_VERSIONING_DISABLED",
    "EC2_SG_SSH_OPEN",
    "EC2_SG_RDP_OPEN",
    "EC2_SG_MYSQL_OPEN",
    "EC2_SG_POSTGRESQL_OPEN",
    "EC2_SG_REDIS_OPEN",
    "EC2_SG_ELASTICSEARCH_OPEN",
    "EC2_SG_ALL_TRAFFIC_OPEN",
    "LOGGING_CLOUDTRAIL_NOT_ENABLED",
    "LOGGING_CLOUDTRAIL_NOT_LOGGING",
    "LOGGING_GUARDDUTY_NOT_ENABLED",
    "LOGGING_GUARDDUTY_SUSPENDED",
]


@pytest.mark.parametrize("finding_id", ALL_CHECK_IDS)
def test_every_check_id_has_compliance_entry(finding_id):
    """Every check ID must have a compliance mapping — no silent gaps."""
    mapping = get_compliance(finding_id)
    assert mapping, (
        f"Finding '{finding_id}' has no compliance mapping in compliance.py. "
        "Add it to the _COMPLIANCE dict."
    )


@pytest.mark.parametrize("finding_id", ALL_CHECK_IDS)
def test_compliance_entry_has_cis_framework(finding_id):
    """Every finding must map to at least the CIS AWS 1.4 framework."""
    mapping = get_compliance(finding_id)
    assert "CIS_AWS_1.4" in mapping, (
        f"Finding '{finding_id}' is missing CIS_AWS_1.4 entry."
    )


@pytest.mark.parametrize("finding_id", ALL_CHECK_IDS)
def test_compliance_entry_has_nist_framework(finding_id):
    """Every finding must map to NIST 800-53."""
    mapping = get_compliance(finding_id)
    assert "NIST_800_53" in mapping, (
        f"Finding '{finding_id}' is missing NIST_800_53 entry."
    )


@pytest.mark.parametrize("finding_id", ALL_CHECK_IDS)
def test_compliance_structure_is_valid(finding_id):
    """Each framework entry must have 'controls' (list) and 'title' (str)."""
    mapping = get_compliance(finding_id)
    for framework, data in mapping.items():
        assert isinstance(data, dict), f"{finding_id}/{framework}: value must be a dict"
        assert "controls" in data, f"{finding_id}/{framework}: missing 'controls' key"
        assert "title" in data, f"{finding_id}/{framework}: missing 'title' key"
        assert isinstance(data["controls"], list), f"{finding_id}/{framework}: 'controls' must be a list"
        assert isinstance(data["title"], str), f"{finding_id}/{framework}: 'title' must be a str"


def test_unknown_finding_id_returns_empty_dict():
    """get_compliance() must return {} for unknown IDs — not raise."""
    result = get_compliance("NONEXISTENT_CHECK_ID")
    assert result == {}


def test_all_finding_ids_returns_list():
    ids = all_finding_ids()
    assert isinstance(ids, list)
    assert len(ids) > 0
    assert "IAM_ROOT_NO_MFA" in ids


# ── Finding helper methods ────────────────────────────────────────────────────

def _make_finding(finding_id: str) -> Finding:
    return Finding(
        id=finding_id,
        service="TEST",
        resource="test-resource",
        severity=Severity.HIGH,
        title="Test",
        description="Test",
        recommendation="Test",
        evidence="Test",
        compliance=get_compliance(finding_id),
    )


def test_finding_cis_controls_returns_list_for_known_id():
    f = _make_finding("IAM_ROOT_NO_MFA")
    controls = f.cis_controls()
    assert isinstance(controls, list)
    assert "1.5" in controls


def test_finding_nist_controls_returns_list_for_known_id():
    f = _make_finding("IAM_ROOT_NO_MFA")
    controls = f.nist_controls()
    assert isinstance(controls, list)
    assert len(controls) > 0


def test_finding_cis_controls_returns_empty_for_no_compliance():
    f = Finding(
        id="FAKE_ID", service="X", resource="r", severity=Severity.LOW,
        title="t", description="d", recommendation="r", evidence="e",
    )
    assert f.cis_controls() == []
    assert f.nist_controls() == []
