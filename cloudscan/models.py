"""
models.py — Core data structures for the scanner.

Every check in checks/ returns List[Finding]. Nothing else.
Reporters in report/ only know about Finding and ScanError — both are decoupled from AWS logic.

ScanError vs Finding:
  Finding  = a security misconfiguration in the AWS account.
  ScanError = a problem with the scanner itself (AccessDenied, API error).
  They are intentionally separate so that "0 findings" cannot be confused with
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


# Ordered from most to least severe — used for --min-severity and --fail-on comparisons.
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
            "metadata": self.metadata,
        }


@dataclass
class ScanError:
    """
    Represents a failure during a check — NOT a security finding.

    Created when:
      - AWS returns AccessDenied (missing IAM permissions)
      - An unexpected API error occurs
      - The check cannot determine the security state of a resource

    Displayed separately from findings so that "0 findings" is never
    confused with "scan failed silently".
    """
    service: str
    check: str
    resource: str
    error_type: str  # "ACCESS_DENIED" | "API_ERROR" | "UNKNOWN"
    message: str

    def to_dict(self) -> dict:
        return {
            "service": self.service,
            "check": self.check,
            "resource": self.resource,
            "error_type": self.error_type,
            "message": self.message,
        }
