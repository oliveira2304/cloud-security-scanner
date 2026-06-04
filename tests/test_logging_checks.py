"""
test_logging_checks.py — Tests for CloudTrail and GuardDuty checks.

Coverage targets:
  - _check_cloudtrail: no trails (CRITICAL), trail exists but not logging (CRITICAL), active (no finding)
  - _check_guardduty: no detectors (HIGH), detector suspended (HIGH), detector enabled (no finding)
  - run(): calls both checks, records errors on AccessDenied
  - Integration: full run(AWSClient) with moto
"""

import boto3
import pytest
from unittest.mock import MagicMock, patch
from botocore.exceptions import ClientError
from moto import mock_aws

from cloudscan.aws_client import AWSClient
from cloudscan.checks.logging_checks import _check_cloudtrail, _check_guardduty, run
from cloudscan.models import Severity


# ── CloudTrail ────────────────────────────────────────────────────────────────

def _make_aws_client(region="us-east-1", account_id="123456789012"):
    client = MagicMock(spec=AWSClient)
    client.region = region
    client.account_id = account_id
    client.errors = []
    return client


def _make_ct_client(trails=None, is_logging=True):
    """Create a mock CloudTrail client."""
    ct = MagicMock()
    trail_list = trails if trails is not None else []
    ct.describe_trails.return_value = {"trailList": trail_list}
    if trail_list:
        ct.get_trail_status.return_value = {"IsLogging": is_logging}
    return ct


def test_cloudtrail_no_trails_reports_critical():
    aws = _make_aws_client()
    aws.get_client = MagicMock(return_value=_make_ct_client(trails=[]))
    findings = _check_cloudtrail(aws)
    assert len(findings) == 1
    assert findings[0].id == "LOGGING_CLOUDTRAIL_NOT_ENABLED"
    assert findings[0].severity == Severity.CRITICAL


def test_cloudtrail_trail_not_logging_reports_critical():
    trail = {"TrailARN": "arn:aws:cloudtrail:us-east-1:123:trail/MyTrail"}
    aws = _make_aws_client()
    aws.get_client = MagicMock(return_value=_make_ct_client(trails=[trail], is_logging=False))
    findings = _check_cloudtrail(aws)
    assert len(findings) == 1
    assert findings[0].id == "LOGGING_CLOUDTRAIL_NOT_LOGGING"
    assert findings[0].severity == Severity.CRITICAL


def test_cloudtrail_active_trail_no_finding():
    trail = {"TrailARN": "arn:aws:cloudtrail:us-east-1:123:trail/MyTrail"}
    aws = _make_aws_client()
    aws.get_client = MagicMock(return_value=_make_ct_client(trails=[trail], is_logging=True))
    findings = _check_cloudtrail(aws)
    assert findings == []


def test_cloudtrail_findings_have_compliance():
    aws = _make_aws_client()
    aws.get_client = MagicMock(return_value=_make_ct_client(trails=[]))
    findings = _check_cloudtrail(aws)
    assert findings[0].compliance
    assert "CIS_AWS_1.4" in findings[0].compliance
    assert findings[0].cis_controls() == ["3.1", "3.2"]


# ── GuardDuty ─────────────────────────────────────────────────────────────────

def _make_gd_client(detector_ids=None, status="ENABLED"):
    gd = MagicMock()
    gd.list_detectors.return_value = {"DetectorIds": detector_ids or []}
    if detector_ids:
        gd.get_detector.return_value = {"Status": status}
    return gd


def test_guardduty_no_detectors_reports_high():
    aws = _make_aws_client()
    aws.get_client = MagicMock(return_value=_make_gd_client(detector_ids=[]))
    findings = _check_guardduty(aws)
    assert len(findings) == 1
    assert findings[0].id == "LOGGING_GUARDDUTY_NOT_ENABLED"
    assert findings[0].severity == Severity.HIGH


def test_guardduty_detector_suspended_reports_high():
    aws = _make_aws_client()
    aws.get_client = MagicMock(return_value=_make_gd_client(
        detector_ids=["det-abc123"], status="SUSPENDED"
    ))
    findings = _check_guardduty(aws)
    assert len(findings) == 1
    assert findings[0].id == "LOGGING_GUARDDUTY_SUSPENDED"
    assert findings[0].severity == Severity.HIGH


def test_guardduty_enabled_no_finding():
    aws = _make_aws_client()
    aws.get_client = MagicMock(return_value=_make_gd_client(
        detector_ids=["det-abc123"], status="ENABLED"
    ))
    findings = _check_guardduty(aws)
    assert findings == []


def test_guardduty_findings_have_compliance():
    aws = _make_aws_client()
    aws.get_client = MagicMock(return_value=_make_gd_client(detector_ids=[]))
    findings = _check_guardduty(aws)
    assert findings[0].compliance
    assert "CIS_AWS_1.4" in findings[0].compliance


# ── run() ─────────────────────────────────────────────────────────────────────

def test_run_records_error_on_cloudtrail_access_denied():
    aws = _make_aws_client()
    ct = MagicMock()
    ct.describe_trails.side_effect = ClientError(
        {"Error": {"Code": "AccessDenied", "Message": "denied"}}, "DescribeTrails"
    )
    gd = _make_gd_client(detector_ids=["det-abc"], status="ENABLED")
    aws.get_client = MagicMock(side_effect=[ct, gd])
    aws.record_error = MagicMock()

    findings = run(aws)

    aws.record_error.assert_called_once()
    call_args = aws.record_error.call_args[0]
    assert call_args[0] == "CloudTrail"


def test_run_records_error_on_guardduty_access_denied():
    aws = _make_aws_client()
    ct = _make_ct_client(trails=[{"TrailARN": "arn:aws:cloudtrail:us-east-1:123:trail/T"}], is_logging=True)
    gd = MagicMock()
    gd.list_detectors.side_effect = ClientError(
        {"Error": {"Code": "AccessDenied", "Message": "denied"}}, "ListDetectors"
    )
    aws.get_client = MagicMock(side_effect=[ct, gd])
    aws.record_error = MagicMock()

    findings = run(aws)

    aws.record_error.assert_called_once()
    call_args = aws.record_error.call_args[0]
    assert call_args[0] == "GuardDuty"


# ── Integration with moto ─────────────────────────────────────────────────────

@mock_aws
def test_logging_run_integration_no_cloudtrail_no_guardduty():
    """
    In a fresh moto account, no CloudTrail trails and no GuardDuty detectors exist.
    Both checks should fire.
    """
    boto3.client("sts", region_name="us-east-1").get_caller_identity()
    client = AWSClient(profile=None, region="us-east-1")
    findings = run(client)

    ids = {f.id for f in findings}
    assert "LOGGING_CLOUDTRAIL_NOT_ENABLED" in ids
    assert "LOGGING_GUARDDUTY_NOT_ENABLED" in ids
    assert client.errors == []
