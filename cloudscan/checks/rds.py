"""
checks/rds.py — RDS security checks.

Checks:
  1. RDS_INSTANCE_PUBLIC          — DB instance with PubliclyAccessible=true (CRITICAL)
  2. RDS_ENCRYPTION_DISABLED      — DB instance without storage encryption (HIGH)
  3. RDS_DELETION_PROTECTION_OFF  — Deletion protection not enabled (MEDIUM)
  4. RDS_MULTI_AZ_DISABLED        — Single-AZ deployment for production DBs (LOW)

Why these checks matter:
  - Public RDS instances bypass VPC security entirely. Any credential leak
    exposes the database directly from the internet.
  - Unencrypted storage violates most compliance frameworks (PCI-DSS, HIPAA,
    SOC 2) and means data is readable if an EBS snapshot is shared.
  - Deletion protection prevents accidental (or malicious) database destruction
    — a common ransomware-adjacent attack in cloud environments.

IAM permissions required:
  rds:DescribeDBInstances
"""

import logging
from typing import List

from botocore.exceptions import ClientError

from cloudscan.aws_client import AWSClient
from cloudscan.compliance import get_compliance
from cloudscan.models import Finding, Severity

logger = logging.getLogger(__name__)


def run(client: AWSClient) -> List[Finding]:
    rds = client.get_client("rds")
    findings: List[Finding] = []

    try:
        paginator = rds.get_paginator("describe_db_instances")
        for page in paginator.paginate():
            for instance in page["DBInstances"]:
                db_id = instance["DBInstanceIdentifier"]
                logger.debug("Scanning RDS instance: %s", db_id)

                findings.extend(_check_public_access(instance))
                findings.extend(_check_encryption(instance))
                findings.extend(_check_deletion_protection(instance))
                findings.extend(_check_multi_az(instance))

    except ClientError as e:
        client.record_error("RDS", "describe_db_instances", "*", e)

    return findings


def _check_public_access(instance: dict) -> List[Finding]:
    if not instance.get("PubliclyAccessible", False):
        return []

    db_id = instance["DBInstanceIdentifier"]
    engine = instance.get("Engine", "unknown")
    endpoint = instance.get("Endpoint", {}).get("Address", "unknown")

    return [Finding(
        id="RDS_INSTANCE_PUBLIC",
        service="RDS",
        resource=db_id,
        severity=Severity.CRITICAL,
        title="RDS instance is publicly accessible",
        description=(
            f"RDS instance '{db_id}' ({engine}) has PubliclyAccessible=true. "
            "The database endpoint is resolvable and reachable from the internet, "
            "bypassing VPC security controls. A credential leak exposes data directly."
        ),
        recommendation=(
            "Set PubliclyAccessible=false and move the instance to a private subnet. "
            "Use a bastion host, VPN, or AWS PrivateLink to access the DB from outside the VPC. "
            "Never expose database ports to the internet."
        ),
        evidence=f"PubliclyAccessible: true, Endpoint: {endpoint}, Engine: {engine}",
        compliance=get_compliance("RDS_INSTANCE_PUBLIC"),
    )]


def _check_encryption(instance: dict) -> List[Finding]:
    if instance.get("StorageEncrypted", False):
        return []

    db_id = instance["DBInstanceIdentifier"]
    engine = instance.get("Engine", "unknown")
    db_class = instance.get("DBInstanceClass", "unknown")

    return [Finding(
        id="RDS_ENCRYPTION_DISABLED",
        service="RDS",
        resource=db_id,
        severity=Severity.HIGH,
        title="RDS instance storage is not encrypted",
        description=(
            f"RDS instance '{db_id}' ({engine}, {db_class}) does not have storage encryption enabled. "
            "Unencrypted storage violates PCI-DSS, HIPAA, and SOC 2 requirements. "
            "EBS snapshots of this instance are also unencrypted."
        ),
        recommendation=(
            "Enable encryption at rest using AWS KMS. "
            "Note: encryption cannot be enabled on existing instances — "
            "you must create an encrypted snapshot and restore from it. "
            "Enable RDS encryption by default in the account settings."
        ),
        evidence=f"StorageEncrypted: false, Engine: {engine}, Class: {db_class}",
        compliance=get_compliance("RDS_ENCRYPTION_DISABLED"),
    )]


def _check_deletion_protection(instance: dict) -> List[Finding]:
    if instance.get("DeletionProtection", False):
        return []

    db_id = instance["DBInstanceIdentifier"]
    engine = instance.get("Engine", "unknown")

    return [Finding(
        id="RDS_DELETION_PROTECTION_OFF",
        service="RDS",
        resource=db_id,
        severity=Severity.MEDIUM,
        title="RDS instance deletion protection is disabled",
        description=(
            f"RDS instance '{db_id}' ({engine}) does not have deletion protection enabled. "
            "Without this, the database can be deleted with a single API call — "
            "either by mistake, a misconfigured automation, or a malicious actor."
        ),
        recommendation=(
            "Enable deletion protection: aws rds modify-db-instance "
            "--db-instance-identifier <id> --deletion-protection. "
            "Also enable automated backups with a retention period >= 7 days."
        ),
        evidence=f"DeletionProtection: false, Engine: {engine}",
        compliance=get_compliance("RDS_DELETION_PROTECTION_OFF"),
    )]


def _check_multi_az(instance: dict) -> List[Finding]:
    """
    Flag single-AZ RDS instances.

    Severity is LOW because this is an availability concern, not a security one.
    Included because it is commonly found in real audits and shows depth.
    """
    if instance.get("MultiAZ", False):
        return []

    db_id = instance["DBInstanceIdentifier"]
    engine = instance.get("Engine", "unknown")

    return [Finding(
        id="RDS_MULTI_AZ_DISABLED",
        service="RDS",
        resource=db_id,
        severity=Severity.LOW,
        title="RDS instance is not Multi-AZ",
        description=(
            f"RDS instance '{db_id}' ({engine}) is deployed in a single Availability Zone. "
            "An AZ failure will cause database downtime until AWS recovers the instance."
        ),
        recommendation=(
            "Enable Multi-AZ for production databases. "
            "The standby replica in another AZ provides automatic failover in ~60-120 seconds."
        ),
        evidence=f"MultiAZ: false, Engine: {engine}",
        compliance=get_compliance("RDS_MULTI_AZ_DISABLED"),
    )]
