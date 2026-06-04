"""
report/json_report.py — JSON output for scan results.

Sprint 1: Added scan_errors and scan_duration to the meta envelope.
"""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

from cloudscan import __version__
from cloudscan.models import Finding, ScanError


def render(
    findings: List[Finding],
    path: str,
    account_id: str = "",
    scan_errors: Optional[List[ScanError]] = None,
    scan_duration: Optional[float] = None,
) -> None:
    scan_errors = scan_errors or []

    report = {
        "meta": {
            "tool": "cloudscan",
            "version": __version__,
            "account_id": account_id,
            "scanned_at": datetime.now(timezone.utc).isoformat(),
            "scan_duration_seconds": round(scan_duration, 2) if scan_duration else None,
            "total_findings": len(findings),
            "severity_counts": _count_by_severity(findings),
            "scan_errors": len(scan_errors),
        },
        "findings": [f.to_dict() for f in findings],
        "scan_errors": [e.to_dict() for e in scan_errors],
    }

    Path(path).write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")


def _count_by_severity(findings: List[Finding]) -> dict:
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        counts[f.severity.value] += 1
    return counts
