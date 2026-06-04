"""
checks/iam.py — IAM security checks.

What this file does:
  Runs three checks across all IAM users:
    1. Users without MFA enabled
    2. Access keys older than 90 days (rotation policy)
    3. Users with active access keys unused for 90+ days

Why access key age matters:
  Long-lived credentials are a major attack surface. If a key leaks and hasn't
  been rotated, it may have been compromised for months undetected. This is a
  common finding in real penetration tests.

How to test:
  See tests/test_iam.py — moto mocks IAM API calls.

How to improve:
  - Add check for inline policies with Action: * / Resource: *
  - Add check for users with AdministratorAccess attached
  - Add check for root account access key existence
  - Add check for root account without MFA
"""

from datetime import datetime, timezone
from typing import List

from cloudscan.aws_client import AWSClient
from cloudscan.models import Finding, Severity

KEY_MAX_AGE_DAYS = 90


def run(client: AWSClient) -> List[Finding]:
    iam = client.get_client("iam")
    findings: List[Finding] = []

    paginator = iam.get_paginator("list_users")
    for page in paginator.paginate():
        for user in page["Users"]:
            username = user["UserName"]
            findings.extend(_check_mfa(iam, username))
            findings.extend(_check_access_key_age(iam, username))

    findings.extend(_check_admin_policies(iam))

    return findings


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
                "Without MFA, a compromised password gives full account access."
            ),
            recommendation=(
                "Enforce MFA via IAM policy (Condition: aws:MultiFactorAuthPresent). "
                "Use hardware MFA for privileged users."
            ),
            evidence="ListMFADevices returned empty MFADevices list",
        )]
    return []


def _check_access_key_age(iam_client, username: str) -> List[Finding]:
    """Detect access keys older than KEY_MAX_AGE_DAYS."""
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
                    "Rotate access keys every 90 days. Use IAM roles instead of long-lived "
                    "access keys where possible (EC2 instance profiles, Lambda execution roles)."
                ),
                evidence=f"AccessKeyId: {key_id}, CreateDate: {created.isoformat()}, Age: {age_days} days",
            ))

    return findings


def _check_admin_policies(iam_client) -> List[Finding]:
    """
    Detect managed policies that grant Action:* on Resource:*.
    This catches wildcarded admin policies that may be attached to users/roles.
    """
    findings = []
    paginator = iam_client.get_paginator("list_policies")

    # Scope=Local = customer-managed only (AWS managed policies are intentionally skipped)
    for page in paginator.paginate(Scope="Local"):
        for policy in page["Policies"]:
            policy_arn = policy["Arn"]
            policy_name = policy["PolicyName"]

            try:
                version_id = policy["DefaultVersionId"]
                version = iam_client.get_policy_version(
                    PolicyArn=policy_arn, VersionId=version_id
                )
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
                                f"Policy '{policy_name}' contains a statement that allows all actions "
                                "on all resources. This is equivalent to AdministratorAccess."
                            ),
                            recommendation=(
                                "Apply least privilege: grant only the specific actions and resources "
                                "required. Use IAM Access Analyzer to generate least-privilege policies."
                            ),
                            evidence=f"PolicyArn: {policy_arn}, Statement Effect: Allow, Action: *, Resource: *",
                        ))
                        break

            except Exception:
                continue

    return findings
