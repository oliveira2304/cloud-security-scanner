"""
models.py — Core data structures for the scanner.

Sprint 2: Added `compliance` field to Finding.

Finding vs ScanError:
  Finding   = a security misconfiguration in the AWS account.
  ScanError = a problem with the scanner itself (AccessDenied, API error).
  Keeping them separate ensures "0 findings" is never confused with
  "the scan failed silently due to missing permissions".
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    def color(self) -> str:
        """Rich markup color for terminal output."""
        return {
            Severity.LOW: "green",
            Severity.MEDIUM: "yellow",
            Severity.HIGH: "red",
            Severity.CRITICAL: "bold red",
        }[self]


# Ordered most → least severe. Used by --min-severity and --fail-on.
SEVERITY_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]


def severity_gte(a: Severity, threshold: Severity) -> bool:
    """Return True if severity `a` is equal to or more severe than `threshold`."""
    return SEVERITY_ORDER.index(a) <= SEVERITY_ORDER.index(threshold)


@dataclass
class Finding:
    id: str
    service: str
    resource: str
    severity: Severity
    title: str
    description: str
    recommendation: str
    evidence: str
    region: Optional[str] = None

    # compliance maps framework name → {controls: [...], title: "..."}
    # Populated from cloudscan/compliance.py via get_compliance(finding_id).
    # Example:
    #   {
    #     "CIS_AWS_1.4": {"controls": ["1.4"], "title": "Ensure no root access key"},
    #     "NIST_800_53":  {"controls": ["AC-6"], "title": "Least Privilege"}
    #   }
    compliance: dict = field(default_factory=dict)

    metadata: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "service": self.service,
            "resource": self.resource,
            "severity": self.severity.value,
            "title": self.title,
            "description": self.description,
            "recommendation": self.recommendation,
            "evidence": self.evidence,
            "region": self.region,
            "compliance": self.compliance,
            "metadata": self.metadata,
        }

    def cis_controls(self) -> list[str]:
        """Return the CIS AWS 1.4 control IDs for this finding, or []."""
        cis = self.compliance.get("CIS_AWS_1.4", {})
        return cis.get("controls", [])

    def nist_controls(self) -> list[str]:
        """Return the NIST 800-53 control IDs for this finding, or []."""
        nist = self.compliance.get("NIST_800_53", {})
        return nist.get("controls", [])


@dataclass
class ScanError:
    """
    Represents a failure during a check — NOT a security finding.

    Created when AWS returns AccessDenied or an unexpected API error occurs.
    Displayed separately so "0 findings" cannot be confused with "scan incomplete".
    """
    service: str
    check: str
    resource: str
    error_type: str  # "ACCESS_DENIED" | "API_ERROR"
    message: str

    def to_dict(self) -> dict:
        return {
            "service": self.service,
            "check": self.check,
            "resource": self.resource,
            "error_type": self.error_type,
            "message": self.message,
        }
