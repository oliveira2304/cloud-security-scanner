"""
checks/logging_checks.py — CloudTrail and GuardDuty checks.

What this file does:
  Checks whether fundamental AWS monitoring services are active:
    1. CloudTrail — is at least one trail logging management events?
    2. GuardDuty — is the detector enabled and not suspended?

Why logging checks matter:
  Without CloudTrail and GuardDuty, an attacker can operate undetected.
  These are the first things a security team enables. Their absence is a
  red flag in any audit.

How to improve:
  - Check CloudTrail log file validation (integrity check)
  - Check CloudTrail multi-region trail status
  - Check if CloudTrail logs are delivered to a separate account (immutability)
  - Check SecurityHub enablement
  - Check Config recorder status
"""

from typing import List

from cloudscan.aws_client import AWSClient
from cloudscan.models import Finding, Severity


def run(client: AWSClient) -> List[Finding]:
    findings: List[Finding] = []
    findings.extend(_check_cloudtrail(client))
    findings.extend(_check_guardduty(client))
    return findings


def _check_cloudtrail(client: AWSClient) -> List[Finding]:
    ct = client.get_client("cloudtrail")

    try:
        trails = ct.describe_trails(includeShadowTrails=False).get("trailList", [])
    except Exception:
        return []

    if not trails:
        return [Finding(
            id="LOGGING_CLOUDTRAIL_NOT_ENABLED",
            service="CloudTrail",
            resource=f"account/{client.account_id}",
            severity=Severity.CRITICAL,
            title="CloudTrail is not enabled",
            description=(
                "No CloudTrail trail found in this region. Without CloudTrail, "
                "API calls are not logged — incident response and forensics are impossible."
            ),
            recommendation=(
                "Enable CloudTrail with a multi-region trail. "
                "Send logs to an S3 bucket in a dedicated logging account. "
                "Enable log file validation."
            ),
            evidence="describe_trails returned empty trailList",
        )]

    # Check if any trail is actually logging
    active = False
    for trail in trails:
        arn = trail.get("TrailARN", "")
        try:
            status = ct.get_trail_status(Name=arn)
            if status.get("IsLogging"):
                active = True
                break
        except Exception:
            continue

    if not active:
        return [Finding(
            id="LOGGING_CLOUDTRAIL_NOT_LOGGING",
            service="CloudTrail",
            resource=f"account/{client.account_id}",
            severity=Severity.CRITICAL,
            title="CloudTrail trail exists but is not logging",
            description="A CloudTrail trail is configured but logging is currently disabled.",
            recommendation="Enable logging on the trail via the console or: aws cloudtrail start-logging --name <trail-arn>",
            evidence=f"Trails found: {len(trails)}, IsLogging: False for all",
        )]

    return []


def _check_guardduty(client: AWSClient) -> List[Finding]:
    gd = client.get_client("guardduty")

    try:
        detectors = gd.list_detectors().get("DetectorIds", [])
    except Exception:
        return []

    if not detectors:
        return [Finding(
            id="LOGGING_GUARDDUTY_NOT_ENABLED",
            service="GuardDuty",
            resource=f"account/{client.account_id}",
            severity=Severity.HIGH,
            title="GuardDuty is not enabled",
            description=(
                "GuardDuty is not enabled in this region. "
                "GuardDuty provides continuous threat detection using ML on CloudTrail, "
                "VPC Flow Logs, and DNS logs."
            ),
            recommendation=(
                "Enable GuardDuty in all regions. "
                "Use AWS Organizations to centrally enable GuardDuty across all accounts."
            ),
            evidence="list_detectors returned empty DetectorIds",
        )]

    for detector_id in detectors:
        try:
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
                )]
        except Exception:
            continue

    return []
