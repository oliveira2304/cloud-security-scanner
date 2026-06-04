"""
Temporary script to generate examples/sample-report.html from sample-output.json.
Run once from the project root: python examples/generate_samples.py
Delete afterwards if you like — it's just a bootstrap helper.
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from cloudscan.models import Finding, Severity
from cloudscan.report import html_report

data = json.loads(Path("examples/sample-output.json").read_text())
findings = [
    Finding(
        id=f["id"],
        service=f["service"],
        resource=f["resource"],
        severity=Severity(f["severity"]),
        title=f["title"],
        description=f["description"],
        recommendation=f["recommendation"],
        evidence=f["evidence"],
        region=f.get("region"),
    )
    for f in data["findings"]
]

html_report.render(
    findings,
    path="examples/sample-report.html",
    account_id=data["meta"]["account_id"],
)
print("Generated examples/sample-report.html")
