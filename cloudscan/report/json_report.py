"""
report/json_report.py — JSON output for the scan results.

What this file does:
  Serializes findings to a structured JSON file. The format is designed to
  be machine-readable — easy to pipe into jq, import into a SIEM, or diff
  between two scans.

Why a top-level envelope:
  Wrapping findings in {"meta": ..., "findings": [...]} means consumers can
  always parse the file structure even when there are zero findings.
  It also stores when the scan ran and which account was scanned.
"""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import List

from cloudscan import __version__
from cloudscan.models import Finding


def render(findings: List[Finding], path: str, account_id: str = "") -> None:
    report = {
        "meta": {
            "tool": "cloudscan",
            "version": __version__,
            "account_id": account_id,
            "scanned_at": datetime.now(timezone.utc).isoformat(),
            "total_findings": len(findings),
            "severity_counts": _count_by_severity(findings),
        },
        "findings": [f.to_dict() for f in findings],
    }

    output_path = Path(path)
    output_path.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")


def _count_by_severity(findings: List[Finding]) -> dict:
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        counts[f.severity.value] += 1
    return counts
