"""
checks/ec2.py — EC2 and Security Group checks.

Error handling: _check_open_ports operates on a dict already fetched by run().
Any ClientError from describe_security_groups is caught in run() and recorded.
"""

import logging
from typing import List

from botocore.exceptions import ClientError

from cloudscan.aws_client import AWSClient
from cloudscan.models import Finding, Severity

logger = logging.getLogger(__name__)

SENSITIVE_PORTS = {
    22:   ("SSH",           Severity.CRITICAL),
    3389: ("RDP",           Severity.CRITICAL),
    3306: ("MySQL",         Severity.HIGH),
    5432: ("PostgreSQL",    Severity.HIGH),
    6379: ("Redis",         Severity.HIGH),
    9200: ("Elasticsearch", Severity.HIGH),
}

PUBLIC_CIDRS = {"0.0.0.0/0", "::/0"}


def run(client: AWSClient) -> List[Finding]:
    ec2 = client.get_client("ec2")
    findings: List[Finding] = []

    try:
        paginator = ec2.get_paginator("describe_security_groups")
        for page in paginator.paginate():
            for sg in page["SecurityGroups"]:
                logger.debug("Scanning Security Group: %s (%s)", sg["GroupId"], sg.get("GroupName"))
                findings.extend(_check_open_ports(sg))
    except ClientError as e:
        client.record_error("EC2", "describe_security_groups", "*", e)

    return findings


def _check_open_ports(sg: dict) -> List[Finding]:
    """Check inbound rules for sensitive ports exposed to public CIDRs."""
    findings = []
    sg_id = sg["GroupId"]
    sg_name = sg.get("GroupName", sg_id)
    resource_label = f"{sg_id} ({sg_name})"

    for rule in sg.get("IpPermissions", []):
        from_port = rule.get("FromPort")
        to_port = rule.get("ToPort")
        protocol = rule.get("IpProtocol", "")

        is_all_traffic = protocol == "-1"

        cidrs = {r["CidrIp"] for r in rule.get("IpRanges", [])}
        cidrs |= {r["CidrIpv6"] for r in rule.get("Ipv6Ranges", [])}
        exposed_cidrs = cidrs & PUBLIC_CIDRS

        if not exposed_cidrs:
            continue

        if is_all_traffic:
            findings.append(Finding(
                id="EC2_SG_ALL_TRAFFIC_OPEN",
                service="EC2",
                resource=resource_label,
                severity=Severity.CRITICAL,
                title="Security Group allows all inbound traffic from the internet",
                description=(
                    f"Security Group '{sg_name}' allows ALL inbound traffic "
                    f"from {', '.join(exposed_cidrs)}. Every port on attached instances is exposed."
                ),
                recommendation=(
                    "Remove the catch-all rule. Allow only specific ports from specific CIDRs. "
                    "Use VPC endpoints and private subnets to avoid public exposure."
                ),
                evidence=f"IpProtocol: -1, CIDRs: {', '.join(exposed_cidrs)}",
            ))
            continue

        for port, (service_name, severity) in SENSITIVE_PORTS.items():
            if _port_in_range(port, from_port, to_port):
                findings.append(Finding(
                    id=f"EC2_SG_{service_name.upper()}_OPEN",
                    service="EC2",
                    resource=resource_label,
                    severity=severity,
                    title=f"Security Group exposes {service_name} port {port} to the internet",
                    description=(
                        f"Security Group '{sg_name}' allows inbound {service_name} (port {port}) "
                        f"from {', '.join(exposed_cidrs)}."
                    ),
                    recommendation=(
                        f"Restrict port {port} to specific trusted IPs or a bastion host CIDR. "
                        "Consider AWS Systems Manager Session Manager instead of SSH/RDP."
                    ),
                    evidence=(
                        f"FromPort: {from_port}, ToPort: {to_port}, "
                        f"Protocol: {protocol}, CIDRs: {', '.join(exposed_cidrs)}"
                    ),
                ))

    return findings


def _port_in_range(port: int, from_port, to_port) -> bool:
    if from_port is None or to_port is None:
        return False
    return from_port <= port <= to_port
