"""
models.py — Core data structures for the scanner.

Every check in checks/ returns List[Finding]. Nothing else.
Reporters in report/ only know about Finding — they are decoupled from AWS logic.
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
    # Extra metadata — checks can attach anything here without breaking the schema
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
