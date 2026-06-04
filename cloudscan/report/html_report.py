"""
report/html_report.py — HTML report generator using Jinja2.

What this file does:
  Renders findings into a self-contained HTML file using the template at
  cloudscan/report/templates/report.html.

Why Jinja2:
  Separates presentation from logic. The template can be redesigned without
  touching Python code. The report is self-contained (inline CSS) so it can
  be shared as a single file attachment.
"""

from datetime import datetime, timezone
from pathlib import Path
from typing import List

from jinja2 import Environment, FileSystemLoader

from cloudscan import __version__
from cloudscan.models import Finding, Severity
from cloudscan.report.json_report import _count_by_severity

TEMPLATE_DIR = Path(__file__).parent / "templates"


def render(findings: List[Finding], path: str, account_id: str = "") -> None:
    env = Environment(loader=FileSystemLoader(str(TEMPLATE_DIR)), autoescape=True)
    template = env.get_template("report.html")

    html = template.render(
        findings=findings,
        account_id=account_id,
        scanned_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        version=__version__,
        severity_counts=_count_by_severity(findings),
        Severity=Severity,
    )

    Path(path).write_text(html, encoding="utf-8")
