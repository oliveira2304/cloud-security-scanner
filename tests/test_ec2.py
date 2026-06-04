"""
test_ec2.py — Unit tests for EC2 / Security Group checks.
"""

import boto3
import pytest
from moto import mock_aws

from cloudscan.checks.ec2 import _check_open_ports, _port_in_range
from cloudscan.models import Severity


def test_port_in_range():
    assert _port_in_range(22, 22, 22) is True
    assert _port_in_range(22, 0, 65535) is True
    assert _port_in_range(22, 80, 443) is False
    assert _port_in_range(22, None, None) is False


@mock_aws
def test_ssh_open_to_world_reports_critical():
    ec2 = boto3.client("ec2", region_name="us-east-1")
    sg = ec2.create_security_group(GroupName="test-sg", Description="test")
    sg_id = sg["GroupId"]

    ec2.authorize_security_group_ingress(
        GroupId=sg_id,
        IpPermissions=[{
            "IpProtocol": "tcp",
            "FromPort": 22,
            "ToPort": 22,
            "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
        }],
    )

    sg_detail = ec2.describe_security_groups(GroupIds=[sg_id])["SecurityGroups"][0]
    findings = _check_open_ports(sg_detail)

    assert len(findings) == 1
    assert findings[0].id == "EC2_SG_SSH_OPEN"
    assert findings[0].severity == Severity.CRITICAL


@mock_aws
def test_rdp_open_to_world_reports_critical():
    ec2 = boto3.client("ec2", region_name="us-east-1")
    sg = ec2.create_security_group(GroupName="rdp-sg", Description="test")
    sg_id = sg["GroupId"]

    ec2.authorize_security_group_ingress(
        GroupId=sg_id,
        IpPermissions=[{
            "IpProtocol": "tcp",
            "FromPort": 3389,
            "ToPort": 3389,
            "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
        }],
    )

    sg_detail = ec2.describe_security_groups(GroupIds=[sg_id])["SecurityGroups"][0]
    findings = _check_open_ports(sg_detail)

    assert any(f.id == "EC2_SG_RDP_OPEN" for f in findings)
    assert all(f.severity == Severity.CRITICAL for f in findings)


@mock_aws
def test_restricted_ssh_no_finding():
    ec2 = boto3.client("ec2", region_name="us-east-1")
    sg = ec2.create_security_group(GroupName="safe-sg", Description="test")
    sg_id = sg["GroupId"]

    ec2.authorize_security_group_ingress(
        GroupId=sg_id,
        IpPermissions=[{
            "IpProtocol": "tcp",
            "FromPort": 22,
            "ToPort": 22,
            "IpRanges": [{"CidrIp": "10.0.0.0/8"}],  # private range only
        }],
    )

    sg_detail = ec2.describe_security_groups(GroupIds=[sg_id])["SecurityGroups"][0]
    findings = _check_open_ports(sg_detail)

    assert findings == []


@mock_aws
def test_mysql_open_to_world_reports_high():
    ec2 = boto3.client("ec2", region_name="us-east-1")
    sg = ec2.create_security_group(GroupName="db-sg", Description="test")
    sg_id = sg["GroupId"]

    ec2.authorize_security_group_ingress(
        GroupId=sg_id,
        IpPermissions=[{
            "IpProtocol": "tcp",
            "FromPort": 3306,
            "ToPort": 3306,
            "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
        }],
    )

    sg_detail = ec2.describe_security_groups(GroupIds=[sg_id])["SecurityGroups"][0]
    findings = _check_open_ports(sg_detail)

    assert len(findings) == 1
    assert findings[0].id == "EC2_SG_MYSQL_OPEN"
    assert findings[0].severity == Severity.HIGH


@mock_aws
def test_all_traffic_open_reports_critical():
    ec2 = boto3.client("ec2", region_name="us-east-1")
    sg = ec2.create_security_group(GroupName="all-open-sg", Description="test")
    sg_id = sg["GroupId"]

    ec2.authorize_security_group_ingress(
        GroupId=sg_id,
        IpPermissions=[{
            "IpProtocol": "-1",  # All traffic
            "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
        }],
    )

    sg_detail = ec2.describe_security_groups(GroupIds=[sg_id])["SecurityGroups"][0]
    findings = _check_open_ports(sg_detail)

    assert len(findings) == 1
    assert findings[0].id == "EC2_SG_ALL_TRAFFIC_OPEN"
    assert findings[0].severity == Severity.CRITICAL
