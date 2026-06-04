"""
checks/ec2.py — EC2 and Security Group checks.

What this file does:
  Scans all Security Groups in the account/region for dangerous inbound rules:
    1. SSH (22) open to 0.0.0.0/0 or ::/0
    2. RDP (3389) open to the world
    3. Sensitive database/cache ports open to the world

Why this matters:
  Security Groups with overly permissive inbound rules are one of the most common
  misconfigurations found in AWS accounts. Exposed SSH/RDP ports are the primary
  vector for brute force and credential stuffing attacks.

SENSITIVE_PORTS — why these specific ports:
  22    SSH  — remote shell
  3389  RDP  — Windows remote desktop
  3306  MySQL/MariaDB — database
  5432  PostgreSQL — database
  6379  Redis — often no auth by default
  9200  Elasticsearch — often no auth, full data exposure

How to improve:
  - Add check for EC2 instances with public IPs and no WAF
  - Add check for instances running as root / without IMDSv2
  - Add check for unencrypted EBS volumes
"""

from typing import List

from cloudscan.aws_client import AWSClient
from cloudscan.models import Finding, Severity

SENSITIVE_PORTS = {
    22: ("SSH", Severity.CRITICAL),
    3389: ("RDP", Severity.CRITICAL),
    3306: ("MySQL", Severity.HIGH),
    5432: ("PostgreSQL", Severity.HIGH),
    6379: ("Redis", Severity.HIGH),
    9200: ("Elasticsearch", Severity.HIGH),
}

PUBLIC_CIDRS = {"0.0.0.0/0", "::/0"}


def run(client: AWSClient) -> List[Finding]:
    ec2 = client.get_client("ec2")
    findings: List[Finding] = []

    paginator = ec2.get_paginator("describe_security_groups")
    for page in paginator.paginate():
        for sg in page["SecurityGroups"]:
            findings.extend(_check_open_ports(sg))

    return findings


def _check_open_ports(sg: dict) -> List[Finding]:
    """Check if any inbound rule exposes a sensitive port to the world."""
    findings = []
    sg_id = sg["GroupId"]
    sg_name = sg.get("GroupName", sg_id)
    resource_label = f"{sg_id} ({sg_name})"

    for rule in sg.get("IpPermissions", []):
        from_port = rule.get("FromPort")
        to_port = rule.get("ToPort")
        protocol = rule.get("IpProtocol", "")

        # Protocol -1 means ALL traffic
        is_all_traffic = protocol == "-1"

        # Collect all CIDRs in this rule
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
                    f"Security Group '{sg_name}' has a rule that allows ALL inbound traffic "
                    f"from {', '.join(exposed_cidrs)}. This exposes every port on attached instances."
                ),
                recommendation=(
                    "Remove the catch-all rule. Allow only specific ports from specific CIDRs. "
                    "Use VPC endpoints and private subnets to avoid public exposure."
                ),
                evidence=f"IpProtocol: -1, CIDRs: {', '.join(exposed_cidrs)}",
            ))
            continue

        # Check each sensitive port
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
                        f"from {', '.join(exposed_cidrs)}. This is a common attack vector."
                    ),
                    recommendation=(
                        f"Restrict port {port} to specific trusted IPs or a bastion host CIDR. "
                        "Consider using AWS Systems Manager Session Manager instead of SSH/RDP."
                    ),
                    evidence=(
                        f"FromPort: {from_port}, ToPort: {to_port}, "
                        f"Protocol: {protocol}, CIDRs: {', '.join(exposed_cidrs)}"
                    ),
                ))

    return findings


def _port_in_range(port: int, from_port, to_port) -> bool:
    """Return True if port falls within [from_port, to_port]."""
    if from_port is None or to_port is None:
        return False
    return from_port <= port <= to_port
