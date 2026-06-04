"""
compliance.py — Maps finding IDs to security framework control references.

Frameworks included:
  CIS_AWS_1.4  — CIS Amazon Web Services Foundations Benchmark v1.4.0
                 The most referenced cloud security baseline.
                 https://www.cisecurity.org/benchmark/amazon_web_services

  NIST_800_53  — NIST SP 800-53 Rev 5 — Security and Privacy Controls
                 Required for FedRAMP and US federal compliance.

Usage in checks:
  from cloudscan.compliance import get_compliance
  Finding(..., compliance=get_compliance("IAM_ROOT_NO_MFA"))

Format:
  {
    "CIS_AWS_1.4": {
        "controls": ["1.5"],
        "title": "Ensure MFA is enabled for the root account"
    },
    "NIST_800_53": {
        "controls": ["IA-2", "IA-2(1)"],
        "title": "Identification and Authentication"
    }
  }
"""

from typing import Dict, Any

ComplianceMap = Dict[str, Any]

_COMPLIANCE: dict[str, ComplianceMap] = {

    # ── IAM: Root account ─────────────────────────────────────────────────────

    "IAM_ROOT_ACCESS_KEY_EXISTS": {
        "CIS_AWS_1.4": {
            "controls": ["1.4"],
            "title": "Ensure no root account access key exists",
        },
        "NIST_800_53": {
            "controls": ["AC-2", "AC-6", "IA-2"],
            "title": "Account Management / Least Privilege",
        },
    },

    "IAM_ROOT_NO_MFA": {
        "CIS_AWS_1.4": {
            "controls": ["1.5"],
            "title": "Ensure MFA is enabled for the root account",
        },
        "NIST_800_53": {
            "controls": ["IA-2", "IA-2(1)", "IA-2(2)"],
            "title": "Identification and Authentication",
        },
    },

    "IAM_ROOT_USED_RECENTLY": {
        "CIS_AWS_1.4": {
            "controls": ["1.7"],
            "title": "Eliminate use of the root user for administrative and daily tasks",
        },
        "NIST_800_53": {
            "controls": ["AC-6", "AC-6(9)"],
            "title": "Least Privilege / Log Use of Privileged Functions",
        },
    },

    # ── IAM: Users ────────────────────────────────────────────────────────────

    "IAM_USER_NO_MFA": {
        "CIS_AWS_1.4": {
            "controls": ["1.10"],
            "title": "Ensure MFA is enabled for all IAM users with a console password",
        },
        "NIST_800_53": {
            "controls": ["IA-2", "IA-2(1)"],
            "title": "Identification and Authentication",
        },
    },

    "IAM_ACCESS_KEY_NOT_ROTATED": {
        "CIS_AWS_1.4": {
            "controls": ["1.14"],
            "title": "Ensure access keys are rotated every 90 days or less",
        },
        "NIST_800_53": {
            "controls": ["IA-5", "IA-5(1)"],
            "title": "Authenticator Management",
        },
    },

    "IAM_POLICY_WILDCARD_ADMIN": {
        "CIS_AWS_1.4": {
            "controls": ["1.16"],
            "title": "Ensure IAM policies that allow full administrative privileges are not attached",
        },
        "NIST_800_53": {
            "controls": ["AC-2", "AC-3", "AC-6"],
            "title": "Account Management / Access Enforcement / Least Privilege",
        },
    },

    # ── S3 ────────────────────────────────────────────────────────────────────

    "S3_PUBLIC_ACCESS_BLOCK_MISSING": {
        "CIS_AWS_1.4": {
            "controls": ["2.1.5"],
            "title": "Ensure that S3 Buckets are configured with Block Public Access",
        },
        "NIST_800_53": {
            "controls": ["AC-3", "AC-17", "SC-7"],
            "title": "Access Enforcement / Remote Access / Boundary Protection",
        },
    },

    "S3_PUBLIC_ACCESS_BLOCK_DISABLED": {
        "CIS_AWS_1.4": {
            "controls": ["2.1.5"],
            "title": "Ensure that S3 Buckets are configured with Block Public Access",
        },
        "NIST_800_53": {
            "controls": ["AC-3", "AC-17", "SC-7"],
            "title": "Access Enforcement / Remote Access / Boundary Protection",
        },
    },

    "S3_ENCRYPTION_DISABLED": {
        "CIS_AWS_1.4": {
            "controls": ["2.1.1"],
            "title": "Ensure all S3 buckets employ encryption-at-rest",
        },
        "NIST_800_53": {
            "controls": ["SC-28", "SC-28(1)"],
            "title": "Protection of Information at Rest",
        },
    },

    "S3_VERSIONING_DISABLED": {
        "CIS_AWS_1.4": {
            "controls": [],
            "title": "S3 versioning best practice (no direct CIS control)",
        },
        "NIST_800_53": {
            "controls": ["CP-9", "CP-10"],
            "title": "Information System Backup / System Recovery and Reconstitution",
        },
    },

    # ── EC2 / Networking ──────────────────────────────────────────────────────

    "EC2_SG_SSH_OPEN": {
        "CIS_AWS_1.4": {
            "controls": ["5.2"],
            "title": "Ensure no security groups allow ingress from 0.0.0.0/0 to port 22",
        },
        "NIST_800_53": {
            "controls": ["AC-17", "CM-7", "SC-7"],
            "title": "Remote Access / Least Functionality / Boundary Protection",
        },
    },

    "EC2_SG_RDP_OPEN": {
        "CIS_AWS_1.4": {
            "controls": ["5.3"],
            "title": "Ensure no security groups allow ingress from 0.0.0.0/0 to port 3389",
        },
        "NIST_800_53": {
            "controls": ["AC-17", "CM-7", "SC-7"],
            "title": "Remote Access / Least Functionality / Boundary Protection",
        },
    },

    "EC2_SG_MYSQL_OPEN": {
        "CIS_AWS_1.4": {
            "controls": ["5.4"],
            "title": "Ensure no security groups allow unrestricted access to database ports",
        },
        "NIST_800_53": {
            "controls": ["CM-7", "SC-7"],
            "title": "Least Functionality / Boundary Protection",
        },
    },

    "EC2_SG_POSTGRESQL_OPEN": {
        "CIS_AWS_1.4": {
            "controls": ["5.4"],
            "title": "Ensure no security groups allow unrestricted access to database ports",
        },
        "NIST_800_53": {
            "controls": ["CM-7", "SC-7"],
            "title": "Least Functionality / Boundary Protection",
        },
    },

    "EC2_SG_REDIS_OPEN": {
        "CIS_AWS_1.4": {
            "controls": ["5.4"],
            "title": "Ensure no security groups allow unrestricted access to database ports",
        },
        "NIST_800_53": {
            "controls": ["CM-7", "SC-7"],
            "title": "Least Functionality / Boundary Protection",
        },
    },

    "EC2_SG_ELASTICSEARCH_OPEN": {
        "CIS_AWS_1.4": {
            "controls": ["5.4"],
            "title": "Ensure no security groups allow unrestricted access to database ports",
        },
        "NIST_800_53": {
            "controls": ["CM-7", "SC-7"],
            "title": "Least Functionality / Boundary Protection",
        },
    },

    "EC2_SG_ALL_TRAFFIC_OPEN": {
        "CIS_AWS_1.4": {
            "controls": ["5.2", "5.3"],
            "title": "Ensure no security groups allow unrestricted inbound access",
        },
        "NIST_800_53": {
            "controls": ["AC-17", "CM-7", "SC-7"],
            "title": "Remote Access / Least Functionality / Boundary Protection",
        },
    },

    # ── Logging & Monitoring ──────────────────────────────────────────────────

    "LOGGING_CLOUDTRAIL_NOT_ENABLED": {
        "CIS_AWS_1.4": {
            "controls": ["3.1", "3.2"],
            "title": "Ensure CloudTrail is enabled in all regions",
        },
        "NIST_800_53": {
            "controls": ["AU-2", "AU-3", "AU-12"],
            "title": "Audit Events / Content of Audit Records / Audit Record Generation",
        },
    },

    "LOGGING_CLOUDTRAIL_NOT_LOGGING": {
        "CIS_AWS_1.4": {
            "controls": ["3.1"],
            "title": "Ensure CloudTrail is enabled in all regions",
        },
        "NIST_800_53": {
            "controls": ["AU-2", "AU-12"],
            "title": "Audit Events / Audit Record Generation",
        },
    },

    "LOGGING_GUARDDUTY_NOT_ENABLED": {
        "CIS_AWS_1.4": {
            "controls": ["3.7"],
            "title": "Ensure AWS GuardDuty is enabled",
        },
        "NIST_800_53": {
            "controls": ["SI-4", "SI-4(2)"],
            "title": "System Monitoring / Automated Tools and Mechanisms for Real-Time Analysis",
        },
    },

    "LOGGING_GUARDDUTY_SUSPENDED": {
        "CIS_AWS_1.4": {
            "controls": ["3.7"],
            "title": "Ensure AWS GuardDuty is enabled",
        },
        "NIST_800_53": {
            "controls": ["SI-4"],
            "title": "System Monitoring",
        },
    },

    # ── RDS ───────────────────────────────────────────────────────────────────

    "RDS_INSTANCE_PUBLIC": {
        "CIS_AWS_1.4": {
            "controls": ["2.3.2"],
            "title": "Ensure that public access is not given to RDS instance",
        },
        "NIST_800_53": {
            "controls": ["AC-3", "AC-17", "SC-7"],
            "title": "Access Enforcement / Remote Access / Boundary Protection",
        },
    },

    "RDS_ENCRYPTION_DISABLED": {
        "CIS_AWS_1.4": {
            "controls": ["2.3.1"],
            "title": "Ensure that encryption-at-rest is enabled for RDS instances",
        },
        "NIST_800_53": {
            "controls": ["SC-28", "SC-28(1)"],
            "title": "Protection of Information at Rest",
        },
    },

    "RDS_DELETION_PROTECTION_OFF": {
        "CIS_AWS_1.4": {
            "controls": [],
            "title": "RDS deletion protection best practice (no direct CIS control)",
        },
        "NIST_800_53": {
            "controls": ["CP-9", "CP-10", "SI-12"],
            "title": "Backup / Recovery / Information Management",
        },
    },

    "RDS_MULTI_AZ_DISABLED": {
        "CIS_AWS_1.4": {
            "controls": [],
            "title": "RDS Multi-AZ best practice (no direct CIS control)",
        },
        "NIST_800_53": {
            "controls": ["CP-6", "CP-7", "CP-9"],
            "title": "Alternate Storage Site / Processing Site / Backup",
        },
    },

    # ── Lambda ────────────────────────────────────────────────────────────────

    "LAMBDA_PUBLIC_URL": {
        "CIS_AWS_1.4": {
            "controls": [],
            "title": "Lambda Function URL public access best practice",
        },
        "NIST_800_53": {
            "controls": ["AC-2", "AC-3", "AC-17", "IA-2"],
            "title": "Account Management / Access Enforcement / Remote Access",
        },
    },

    "LAMBDA_ENV_SECRET_EXPOSURE": {
        "CIS_AWS_1.4": {
            "controls": [],
            "title": "Lambda secrets management best practice",
        },
        "NIST_800_53": {
            "controls": ["IA-5", "IA-5(7)", "SC-28"],
            "title": "Authenticator Management / No Embedded Unencrypted Secrets",
        },
    },
}


def get_compliance(finding_id: str) -> ComplianceMap:
    """Return the compliance mapping for a given finding ID. Empty dict if none."""
    return _COMPLIANCE.get(finding_id, {})


def all_finding_ids() -> list[str]:
    """Return all finding IDs that have a compliance mapping. Used in tests."""
    return list(_COMPLIANCE.keys())
