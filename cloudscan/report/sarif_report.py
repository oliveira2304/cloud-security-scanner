"""
report/sarif_report.py — SARIF 2.1.0 output.

SARIF (Static Analysis Results Interchange Format) is the standard format
for security tool output. GitHub's Security tab natively ingests SARIF files
uploaded via the `github/codeql-action/upload-sarif` action, showing findings
as code scanning alerts on the repository.

Why SARIF matters for a portfolio:
  Any recruiter or engineer who opens the GitHub repo will see security findings
  directly in the Security tab — no need to run the tool or read a JSON file.
  It demonstrates knowledge of the DevSecOps toolchain.

SARIF level mapping (from SARIF spec):
  CRITICAL → "error"
  HIGH     → "error"
  MEDIUM   → "warning"
  LOW      → "note"

AWS resource URIs:
  SARIF expects file/code locations, but we are scanning cloud resources.
  We use logical locations with a custom URI scheme (aws://<service>/<resource>)
  which renders cleanly in GitHub's UI and is a common pattern for cloud scanners.

References:
  https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
  https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/sarif-support-for-code-scanning
"""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import List

from cloudscan import __version__
from cloudscan.models import Finding, Severity

_SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
_REPO_URL = "https://github.com/oliveira2304/cloud-security-scanner"

_LEVEL_MAP = {
    Severity.CRITICAL: "error",
    Severity.HIGH:     "error",
    Severity.MEDIUM:   "warning",
    Severity.LOW:      "note",
}


def render(findings: List[Finding], path: str, account_id: str = "") -> None:
    rules = _build_rules(findings)
    results = [_finding_to_result(f) for f in findings]

    sarif = {
        "$schema": _SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "cloudscan",
                        "version": __version__,
                        "informationUri": _REPO_URL,
                        "rules": rules,
                    }
                },
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "endTimeUtc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                        "properties": {"account_id": account_id},
                    }
                ],
                "results": results,
            }
        ],
    }

    Path(path).write_text(json.dumps(sarif, indent=2), encoding="utf-8")


def _build_rules(findings: List[Finding]) -> list:
    """
    Build the rules array — one entry per unique finding ID.
    SARIF rules describe *what* can be found; results describe *where* it was found.
    """
    seen: dict[str, Finding] = {}
    for f in findings:
        if f.id not in seen:
            seen[f.id] = f

    rules = []
    for finding_id, f in seen.items():
        cis_controls = f.cis_controls()
        tags = [f.service, "security", "aws", f.severity.value.lower()]
        if cis_controls:
            tags += [f"CIS_{c}" for c in cis_controls]

        rule = {
            "id": finding_id,
            "name": _to_pascal_case(finding_id),
            "shortDescription": {"text": f.title},
            "fullDescription": {"text": f.description},
            "helpUri": _REPO_URL,
            "help": {
                "text": f.recommendation,
                "markdown": f"**Recommendation:** {f.recommendation}",
            },
            "properties": {
                "tags": tags,
                "severity": f.severity.value,
                "precision": "high",
            },
            "defaultConfiguration": {
                "level": _LEVEL_MAP[f.severity],
            },
        }

        # Add compliance info to rule properties if available
        if f.compliance:
            rule["properties"]["compliance"] = {
                framework: data.get("controls", [])
                for framework, data in f.compliance.items()
                if data.get("controls")
            }

        rules.append(rule)

    return rules


def _finding_to_result(f: Finding) -> dict:
    """Convert a Finding to a SARIF result object."""
    resource_uri = f"aws://{f.service.lower()}/{f.resource}"

    result = {
        "ruleId": f.id,
        "level": _LEVEL_MAP[f.severity],
        "message": {
            "text": f"{f.title} — {f.description}",
        },
        "locations": [
            {
                "logicalLocations": [
                    {
                        "name": f.resource,
                        "kind": f.service.lower(),
                        "fullyQualifiedName": resource_uri,
                    }
                ]
            }
        ],
        "properties": {
            "service": f.service,
            "resource": f.resource,
            "severity": f.severity.value,
            "evidence": f.evidence,
            "recommendation": f.recommendation,
        },
    }

    if f.region:
        result["properties"]["region"] = f.region

    if f.compliance:
        cis = f.cis_controls()
        if cis:
            result["properties"]["cis_controls"] = cis

    return result


def _to_pascal_case(snake_str: str) -> str:
    """EC2_SG_SSH_OPEN → Ec2SgSshOpen"""
    return "".join(word.capitalize() for word in snake_str.split("_"))
