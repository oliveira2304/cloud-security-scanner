"""
test_multiregion.py — Tests for multi-region orchestration.

These tests verify:
  - for_region() reuses the same session without extra STS calls
  - for_region() shares the errors list
  - run_all_regions() aggregates findings from multiple regions
  - Global services (IAM) run once, not per region
  - Findings are tagged with their region
"""

from unittest.mock import MagicMock, patch, call
import pytest

from cloudscan.aws_client import AWSClient
from cloudscan.checks import run_all_regions, GLOBAL_SERVICES
from cloudscan.models import Finding, Severity


def _make_finding(region=None) -> Finding:
    return Finding(
        id="TEST_FINDING", service="S3", resource="bucket",
        severity=Severity.HIGH, title="T", description="D",
        recommendation="R", evidence="E", region=region,
    )


# ── AWSClient.for_region() ────────────────────────────────────────────────────

def test_for_region_reuses_session():
    """for_region() must not create a new boto3 session."""
    client = MagicMock(spec=AWSClient)
    client.profile = "default"
    client.region = "us-east-1"
    client.errors = []
    client._session = MagicMock()
    client._account_id = "123456789012"

    regional = AWSClient.for_region(client, "eu-west-1")

    assert regional._session is client._session
    assert regional.region == "eu-west-1"
    assert regional._account_id == "123456789012"


def test_for_region_shares_errors_list():
    """Errors from regional scans must appear in the parent client's error list."""
    client = MagicMock(spec=AWSClient)
    client.profile = "default"          # spec=AWSClient needs explicit attrs set
    client.errors = []
    client._session = MagicMock()
    client._account_id = "123"

    regional = AWSClient.for_region(client, "ap-southeast-1")
    assert regional.errors is client.errors


# ── run_all_regions() ─────────────────────────────────────────────────────────

def test_run_all_regions_tags_findings_with_region():
    """Findings with region=None must be tagged with their scan region."""
    untagged_finding = _make_finding(region=None)

    mock_check = MagicMock(return_value=[untagged_finding])

    with patch.dict("cloudscan.checks.REGISTRY", {"s3": mock_check}):
        client = MagicMock(spec=AWSClient)
        client.region = "us-east-1"
        client.errors = []
        client._session = MagicMock()
        client._account_id = "123"

        # for_region must return a proper mock
        regional = MagicMock(spec=AWSClient)
        regional.region = "eu-west-1"
        regional.errors = client.errors
        regional._session = client._session
        regional._account_id = "123"
        client.for_region.return_value = regional

        findings = run_all_regions(client, ["s3"], ["eu-west-1"])

    assert len(findings) == 1
    assert findings[0].region == "eu-west-1"


def test_iam_is_in_global_services():
    assert "iam" in GLOBAL_SERVICES


def test_global_services_run_once_not_per_region():
    """IAM is global — it should run exactly once regardless of how many regions."""
    mock_iam = MagicMock(return_value=[_make_finding()])

    with patch.dict("cloudscan.checks.REGISTRY", {"iam": mock_iam}):
        client = MagicMock(spec=AWSClient)
        client.region = "us-east-1"
        client.errors = []
        client._session = MagicMock()
        client._account_id = "123"
        client.for_region.return_value = client

        run_all_regions(client, ["iam"], ["us-east-1", "eu-west-1", "ap-southeast-1"])

    # Must have been called exactly once, not once per region
    assert mock_iam.call_count == 1


def test_regional_services_run_per_region():
    """EC2 is regional — it should run once per region."""
    mock_ec2 = MagicMock(return_value=[])

    regional_mock = MagicMock(spec=AWSClient)
    regional_mock.region = "eu-west-1"
    regional_mock.errors = []
    regional_mock._session = MagicMock()
    regional_mock._account_id = "123"

    with patch.dict("cloudscan.checks.REGISTRY", {"ec2": mock_ec2}):
        client = MagicMock(spec=AWSClient)
        client.region = "us-east-1"
        client.errors = []
        client._session = MagicMock()
        client._account_id = "123"
        client.for_region.return_value = regional_mock

        run_all_regions(client, ["ec2"], ["us-east-1", "eu-west-1"])

    assert mock_ec2.call_count == 2


def test_progress_callback_called():
    """progress_callback must be called once per completed check."""
    mock_s3 = MagicMock(return_value=[_make_finding()])
    calls = []

    regional = MagicMock(spec=AWSClient)
    regional.region = "us-east-1"
    regional.errors = []
    regional._session = MagicMock()
    regional._account_id = "123"

    with patch.dict("cloudscan.checks.REGISTRY", {"s3": mock_s3}):
        client = MagicMock(spec=AWSClient)
        client.region = "us-east-1"
        client.errors = []
        client._session = MagicMock()
        client._account_id = "123"
        client.for_region.return_value = regional

        run_all_regions(
            client, ["s3"], ["us-east-1"],
            progress_callback=lambda r, s, n: calls.append((r, s, n)),
        )

    assert len(calls) == 1
    region, service, n_findings = calls[0]
    assert service == "s3"
    assert n_findings == 1
