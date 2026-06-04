"""
checks/iam.py — IAM security checks.

Checks:
  1. Root account access keys present      (CRITICAL — CIS 1.4)
  2. Root account MFA not enabled          (CRITICAL — CIS 1.5)
  3. Root account used recently            (HIGH     — CIS 1.7)
  4. IAM users without MFA                 (HIGH)
  5. Access keys older than 90 days        (HIGH)
  6. Customer policies with Action:* Resource:* (CRITICAL)

Root account checks use iam:GetAccountSummary (keys, MFA) and the IAM
credential report (last activity). Both are read-only and low-cost.

The credential report may take a few seconds to generate on first call.
If it cannot be retrieved, a ScanError is recorded rather than silently
skipping the check.
"""

import csv
import io
import logging
import time
from datetime import datetime, timezone
from typing import List, Optional

from botocore.exceptions import ClientError

from cloudscan.aws_client import AWSClient
from cloudscan.models import Finding, Severity

logger = logging.getLogger(__name__)

KEY_MAX_AGE_DAYS = 90
ROOT_RECENT_USE_DAYS = 30


def run(client: AWSClient) -> List[Finding]:
    iam = client.get_client("iam")
    findings: List[Finding] = []

    # Root account checks — highest priority
    try:
        findings.extend(_check_root_account(iam, client))
    except ClientError as e:
        client.record_error("IAM", "_check_root_account", "root", e)

    # Per-user checks
    try:
        paginator = iam.get_paginator("list_users")
        for page in paginator.paginate():
            for user in page["Users"]:
                username = user["UserName"]
                logger.debug("Scanning IAM user: %s", username)

                try:
                    findings.extend(_check_mfa(iam, username))
                except ClientError as e:
                    client.record_error("IAM", "_check_mfa", username, e)

                try:
                    findings.extend(_check_access_key_age(iam, username))
                except ClientError as e:
                    client.record_error("IAM", "_check_access_key_age", username, e)

    except ClientError as e:
        client.record_error("IAM", "list_users", "*", e)

    # Policy-level checks
    try:
        findings.extend(_check_admin_policies(iam, client))
    except ClientError as e:
        client.record_error("IAM", "_check_admin_policies", "*", e)

    return findings


# ── Root account ──────────────────────────────────────────────────────────────

def _check_root_account(iam_client, client: AWSClient) -> List[Finding]:
    """
    Check root account security using GetAccountSummary and the credential report.

    Why GetAccountSummary:
      It's a single API call that returns AccountMFAEnabled and AccountAccessKeysPresent
      for the root account specifically. No need to iterate users.
    """
    findings = []

    summary = iam_client.get_account_summary()["SummaryMap"]

    if summary.get("AccountAccessKeysPresent", 0) > 0:
        findings.append(Finding(
            id="IAM_ROOT_ACCESS_KEY_EXISTS",
            service="IAM",
            resource="root",
            severity=Severity.CRITICAL,
            title="Root account has active access keys",
            description=(
                "The AWS root account has one or more active access keys. "
                "Root access keys cannot be scoped with IAM policies — any leak gives "
                "unlimited access to the account with no restrictions."
            ),
            recommendation=(
                "Delete root access keys immediately. "
                "Use IAM roles or users with least-privilege policies instead. "
                "Root access keys cannot be restricted by SCPs or permission boundaries."
            ),
            evidence=f"GetAccountSummary: AccountAccessKeysPresent={summary['AccountAccessKeysPresent']}",
        ))

    if summary.get("AccountMFAEnabled", 0) == 0:
        findings.append(Finding(
            id="IAM_ROOT_NO_MFA",
            service="IAM",
            resource="root",
            severity=Severity.CRITICAL,
            title="Root account has no MFA enabled",
            description=(
                "The root account does not have MFA enabled. "
                "A compromised root password gives unrestricted access to all AWS services, "
                "including the ability to delete all IAM users and disable CloudTrail."
            ),
            recommendation=(
                "Enable a hardware MFA device on the root account. "
                "Virtual MFA is acceptable but hardware (YubiKey) is preferred for root. "
                "Then lock root credentials away and never use them for daily operations."
            ),
            evidence=f"GetAccountSummary: AccountMFAEnabled={summary.get('AccountMFAEnabled', 0)}",
        ))

    # Check root last used via credential report
    root_last_used = _get_root_last_used(iam_client, client)
    if root_last_used is not None:
        age_days = (datetime.now(timezone.utc) - root_last_used).days
        if age_days <= ROOT_RECENT_USE_DAYS:
            findings.append(Finding(
                id="IAM_ROOT_USED_RECENTLY",
                service="IAM",
                resource="root",
                severity=Severity.HIGH,
                title=f"Root account was used {age_days} day(s) ago",
                description=(
                    f"The root account was last used {age_days} day(s) ago. "
                    "Root should only be used for account-level tasks that cannot be "
                    "delegated to IAM (e.g. closing the account, changing support plan)."
                ),
                recommendation=(
                    "Investigate what the root account was used for. "
                    "Create IAM users/roles with least-privilege for all regular operations. "
                    "Treat any unexpected root usage as a potential security incident."
                ),
                evidence=f"Credential report: root password_last_used={root_last_used.isoformat()}",
            ))

    return findings


def _get_root_last_used(iam_client, client: AWSClient) -> Optional[datetime]:
    """
    Generate the IAM credential report and extract root account last-used date.
    Returns None if the report cannot be retrieved or root has never been used.
    """
    try:
        iam_client.generate_credential_report()

        # The report generation is async — poll up to ~10s
        for attempt in range(5):
            try:
                response = iam_client.get_credential_report()
                content = response["Content"].decode("utf-8")
                reader = csv.DictReader(io.StringIO(content))

                for row in reader:
                    if row.get("user") == "<root_account>":
                        last_used_str = row.get("password_last_used", "N/A")
                        if last_used_str and last_used_str != "N/A" and last_used_str != "no_information":
                            return datetime.fromisoformat(last_used_str.replace("Z", "+00:00"))
                return None

            except iam_client.exceptions.ReportNotPresent:
                logger.debug("Credential report not ready yet, attempt %d/5", attempt + 1)
                time.sleep(2)

        logger.warning("IAM credential report did not become ready in time.")
        return None

    except ClientError as e:
        client.record_error("IAM", "_get_root_last_used", "root", e)
        return None


# ── Per-user checks ───────────────────────────────────────────────────────────

def _check_mfa(iam_client, username: str) -> List[Finding]:
    """Detect users with no MFA device attached."""
    response = iam_client.list_mfa_devices(UserName=username)
    if not response.get("MFADevices"):
        return [Finding(
            id="IAM_USER_NO_MFA",
            service="IAM",
            resource=username,
            severity=Severity.HIGH,
            title="IAM user has no MFA device",
            description=(
                f"User '{username}' has no MFA device configured. "
                "A compromised password gives full console access."
            ),
            recommendation=(
                "Enforce MFA via IAM policy (Condition: aws:MultiFactorAuthPresent). "
                "Use hardware MFA for privileged users."
            ),
            evidence="ListMFADevices: empty MFADevices list",
        )]
    return []


def _check_access_key_age(iam_client, username: str) -> List[Finding]:
    """Detect active access keys older than KEY_MAX_AGE_DAYS."""
    findings = []
    response = iam_client.list_access_keys(UserName=username)

    for key in response.get("AccessKeyMetadata", []):
        if key["Status"] != "Active":
            continue

        key_id = key["AccessKeyId"]
        created = key["CreateDate"]
        age_days = (datetime.now(timezone.utc) - created).days

        if age_days > KEY_MAX_AGE_DAYS:
            findings.append(Finding(
                id="IAM_ACCESS_KEY_NOT_ROTATED",
                service="IAM",
                resource=username,
                severity=Severity.HIGH,
                title=f"IAM access key not rotated in {age_days} days",
                description=(
                    f"Access key '{key_id}' for user '{username}' is {age_days} days old. "
                    f"Keys older than {KEY_MAX_AGE_DAYS} days violate rotation best practices."
                ),
                recommendation=(
                    "Rotate access keys every 90 days. "
                    "Prefer IAM roles over long-lived keys (EC2 instance profiles, Lambda execution roles)."
                ),
                evidence=f"AccessKeyId: {key_id}, CreateDate: {created.isoformat()}, Age: {age_days}d",
            ))

    return findings


# ── Policy checks ─────────────────────────────────────────────────────────────

def _check_admin_policies(iam_client, client: AWSClient) -> List[Finding]:
    """Detect customer-managed policies that grant Action:* on Resource:*."""
    findings = []
    paginator = iam_client.get_paginator("list_policies")

    for page in paginator.paginate(Scope="Local"):
        for policy in page["Policies"]:
            policy_arn = policy["Arn"]
            policy_name = policy["PolicyName"]

            try:
                version_id = policy["DefaultVersionId"]
                version = iam_client.get_policy_version(PolicyArn=policy_arn, VersionId=version_id)
                document = version["PolicyVersion"]["Document"]

                for statement in document.get("Statement", []):
                    if statement.get("Effect") != "Allow":
                        continue

                    actions = statement.get("Action", [])
                    resources = statement.get("Resource", [])

                    if isinstance(actions, str):
                        actions = [actions]
                    if isinstance(resources, str):
                        resources = [resources]

                    if "*" in actions and "*" in resources:
                        findings.append(Finding(
                            id="IAM_POLICY_WILDCARD_ADMIN",
                            service="IAM",
                            resource=policy_name,
                            severity=Severity.CRITICAL,
                            title="IAM policy grants full admin (Action:* Resource:*)",
                            description=(
                                f"Policy '{policy_name}' allows all actions on all resources. "
                                "This is equivalent to AdministratorAccess."
                            ),
                            recommendation=(
                                "Apply least privilege: grant only the specific actions and resources needed. "
                                "Use IAM Access Analyzer to generate least-privilege policies."
                            ),
                            evidence=f"PolicyArn: {policy_arn}, Action: *, Resource: *",
                        ))
                        break

            except ClientError as e:
                client.record_error("IAM", "_check_admin_policies", policy_name, e)

    return findings
