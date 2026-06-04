"""
report/terminal.py — Rich terminal output.

What this file does:
  Takes a list of Finding objects and renders them as a formatted table
  in the terminal using the Rich library.

Why Rich:
  - Zero-config colors, tables, and progress spinners.
  - Output is readable even in plain text (degrades gracefully when no TTY).
  - The summary panel gives a quick at-a-glance status.

How to extend:
  - Add a --quiet flag that only shows HIGH/CRITICAL findings.
  - Add a progress bar (rich.progress) while checks are running.
"""

from collections import Counter
from typing import List

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box

from cloudscan.models import Finding, Severity

console = Console()

SEVERITY_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]


def render(findings: List[Finding], account_id: str = "") -> None:
    """Print all findings as a Rich table, then show a summary panel."""
    if not findings:
        console.print("\n[bold green]No findings detected. Account looks clean![/bold green]\n")
        return

    # Sort by severity (CRITICAL first) then service
    sorted_findings = sorted(
        findings,
        key=lambda f: (SEVERITY_ORDER.index(f.severity), f.service),
    )

    table = Table(
        title=f"[bold]Cloud Security Scan Results[/bold]  •  Account: {account_id}",
        box=box.ROUNDED,
        show_lines=True,
        highlight=True,
    )

    table.add_column("Severity", style="bold", width=10, justify="center")
    table.add_column("Service", style="cyan", width=12)
    table.add_column("Resource", width=30, overflow="fold")
    table.add_column("Title", width=45, overflow="fold")
    table.add_column("Evidence", width=40, overflow="fold")

    for f in sorted_findings:
        color = f.severity.color()
        table.add_row(
            f"[{color}]{f.severity.value}[/{color}]",
            f.service,
            f.resource,
            f.title,
            f.evidence,
        )

    console.print()
    console.print(table)
    console.print()

    _render_summary(findings, account_id)


def _render_summary(findings: List[Finding], account_id: str) -> None:
    counts = Counter(f.severity for f in findings)

    lines = [
        f"[bold]Account:[/bold] {account_id}",
        f"[bold]Total findings:[/bold] {len(findings)}",
        "",
        f"  [bold red]  CRITICAL[/bold red]  {counts.get(Severity.CRITICAL, 0)}",
        f"  [red]     HIGH[/red]  {counts.get(Severity.HIGH, 0)}",
        f"  [yellow]   MEDIUM[/yellow]  {counts.get(Severity.MEDIUM, 0)}",
        f"  [green]      LOW[/green]  {counts.get(Severity.LOW, 0)}",
    ]

    has_critical = counts.get(Severity.CRITICAL, 0) > 0
    border_color = "red" if has_critical else "yellow"

    console.print(Panel(
        "\n".join(lines),
        title="[bold]Scan Summary[/bold]",
        border_style=border_color,
        expand=False,
    ))
    console.print()
