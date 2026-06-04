"""
checks/logging_checks.py — CloudTrail and GuardDuty checks.
"""

import logging
from typing import List

from botocore.exceptions import ClientError

from cloudscan.aws_client import AWSClient
from cloudscan.compliance import get_compliance
from cloudscan.models import Finding, Severity

logger = logging.getLogger(__name__)


def run(client: AWSClient) -> List[Finding]:
    findings: List[Finding] = []

    try:
        findings.extend(_check_cloudtrail(client))
    except ClientError as e:
        client.record_error("CloudTrail", "_check_cloudtrail", "*", e)

    try:
        findings.extend(_check_guardduty(client))
    except ClientError as e:
        client.record_error("GuardDuty", "_check_guardduty", "*", e)

    return findings


def _check_cloudtrail(client: AWSClient) -> List[Finding]:
    ct = client.get_client("cloudtrail")
    trails = ct.describe_trails(includeShadowTrails=False).get("trailList", [])

    if not trails:
        return [Finding(
            id="LOGGING_CLOUDTRAIL_NOT_ENABLED",
            service="CloudTrail",
            resource=f"account/{client.account_id}",
            severity=Severity.CRITICAL,
            title="CloudTrail is not enabled",
            description=(
                "No CloudTrail trail found in this region. "
                "Without CloudTrail, API calls are not logged — "
                "incident response and forensics are impossible."
            ),
            recommendation=(
                "Enable CloudTrail with a multi-region trail. "
                "Send logs to an S3 bucket in a dedicated logging account. "
                "Enable log file validation."
            ),
            evidence="describe_trails: empty trailList",
            compliance=get_compliance("LOGGING_CLOUDTRAIL_NOT_ENABLED"),
        )]

    active = False
    for trail in trails:
        arn = trail.get("TrailARN", "")
        try:
            status = ct.get_trail_status(Name=arn)
            if status.get("IsLogging"):
                active = True
                break
        except ClientError as e:
            logger.warning("Could not get trail status for %s: %s", arn, e)

    if not active:
        return [Finding(
            id="LOGGING_CLOUDTRAIL_NOT_LOGGING",
            service="CloudTrail",
            resource=f"account/{client.account_id}",
            severity=Severity.CRITICAL,
            title="CloudTrail trail exists but is not logging",
            description="A CloudTrail trail is configured but logging is currently disabled.",
            recommendation="Enable logging: aws cloudtrail start-logging --name <trail-arn>",
            evidence=f"Trails found: {len(trails)}, IsLogging: False for all",
            compliance=get_compliance("LOGGING_CLOUDTRAIL_NOT_LOGGING"),
        )]

    return []


def _check_guardduty(client: AWSClient) -> List[Finding]:
    gd = client.get_client("guardduty")
    detectors = gd.list_detectors().get("DetectorIds", [])

    if not detectors:
        return [Finding(
            id="LOGGING_GUARDDUTY_NOT_ENABLED",
            service="GuardDuty",
            resource=f"account/{client.account_id}",
            severity=Severity.HIGH,
            title="GuardDuty is not enabled",
            description=(
                "GuardDuty is not enabled in this region. "
                "GuardDuty provides continuous threat detection using ML on "
                "CloudTrail, VPC Flow Logs, and DNS logs."
            ),
            recommendation=(
                "Enable GuardDuty in all regions. "
                "Use AWS Organizations to centrally enable it across all accounts."
            ),
            evidence="list_detectors: empty DetectorIds",
            compliance=get_compliance("LOGGING_GUARDDUTY_NOT_ENABLED"),
        )]

    for detector_id in detectors:
        detail = gd.get_detector(DetectorId=detector_id)
        if detail.get("Status") != "ENABLED":
            return [Finding(
                id="LOGGING_GUARDDUTY_SUSPENDED",
                service="GuardDuty",
                resource=detector_id,
                severity=Severity.HIGH,
                title="GuardDuty detector is suspended",
                description="A GuardDuty detector exists but is not in ENABLED state.",
                recommendation="Re-enable GuardDuty. Investigate why it was suspended.",
                evidence=f"DetectorId: {detector_id}, Status: {detail.get('Status')}",
                compliance=get_compliance("LOGGING_GUARDDUTY_SUSPENDED"),
            )]

    return []
