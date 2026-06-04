"""
report/terminal.py — Rich terminal output.

Sprint 1 additions:
  - quiet: show only the summary panel, skip the findings table.
  - min_severity: filter displayed findings to >= threshold.
  - scan_errors: show a separate "Scan Warnings" section when checks failed.
  - scan_duration: show total scan time in the summary panel.

Note on min_severity vs --fail-on:
  min_severity affects DISPLAY only.
  --fail-on is evaluated by main.py against the FULL finding list before this
  function is called. So `--min-severity HIGH --fail-on CRITICAL` still fails
  correctly if there are hidden MEDIUM findings — they just won't appear in the table.
"""

from collections import Counter
from typing import List, Optional

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box

from cloudscan.models import Finding, ScanError, Severity, SEVERITY_ORDER, severity_gte

console = Console()


def render(
    findings: List[Finding],
    account_id: str = "",
    quiet: bool = False,
    min_severity: Optional[Severity] = None,
    scan_errors: Optional[List[ScanError]] = None,
    scan_duration: Optional[float] = None,
) -> None:
    scan_errors = scan_errors or []

    # Apply min_severity filter for display (does not affect --fail-on)
    display_findings = findings
    if min_severity is not None:
        display_findings = [f for f in findings if severity_gte(f.severity, min_severity)]

    if not display_findings and not quiet:
        if not findings:
            console.print("\n[bold green]No findings detected.[/bold green]\n")
        else:
            console.print(
                f"\n[dim]No findings at or above {min_severity.value} severity. "
                f"({len(findings)} lower-severity finding(s) hidden.)[/dim]\n"
            )

    if not quiet and display_findings:
        _render_table(display_findings, account_id)

    _render_summary(findings, display_findings, account_id, scan_errors, scan_duration, min_severity)

    if scan_errors:
        _render_scan_errors(scan_errors)


def _render_table(findings: List[Finding], account_id: str) -> None:
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
    table.add_column("Service",  style="cyan", width=12)
    table.add_column("Resource", width=30, overflow="fold")
    table.add_column("Title",    width=45, overflow="fold")
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


def _render_summary(
    all_findings: List[Finding],
    display_findings: List[Finding],
    account_id: str,
    scan_errors: List[ScanError],
    scan_duration: Optional[float],
    min_severity: Optional[Severity],
) -> None:
    counts = Counter(f.severity for f in all_findings)
    hidden = len(all_findings) - len(display_findings)

    lines = [
        f"[bold]Account:[/bold]        {account_id}",
        f"[bold]Total findings:[/bold] {len(all_findings)}",
    ]

    if min_severity and hidden > 0:
        lines.append(f"[dim]Showing >= {min_severity.value} ({hidden} hidden)[/dim]")

    lines += [
        "",
        f"  [bold red]  CRITICAL[/bold red]  {counts.get(Severity.CRITICAL, 0)}",
        f"  [red]     HIGH[/red]  {counts.get(Severity.HIGH, 0)}",
        f"  [yellow]   MEDIUM[/yellow]  {counts.get(Severity.MEDIUM, 0)}",
        f"  [green]      LOW[/green]  {counts.get(Severity.LOW, 0)}",
    ]

    if scan_errors:
        lines.append(f"\n  [yellow]Scan warnings: {len(scan_errors)}[/yellow] (see below)")

    if scan_duration is not None:
        lines.append(f"\n[dim]Scan completed in {scan_duration:.1f}s[/dim]")

    has_critical = counts.get(Severity.CRITICAL, 0) > 0
    border_color = "red" if has_critical else ("yellow" if counts.get(Severity.HIGH, 0) > 0 else "green")

    console.print(Panel(
        "\n".join(lines),
        title="[bold]Scan Summary[/bold]",
        border_style=border_color,
        expand=False,
    ))
    console.print()


def _render_scan_errors(scan_errors: List[ScanError]) -> None:
    """Show a distinct section for scan errors — separate from security findings."""
    table = Table(
        title="[bold yellow]Scan Warnings — checks that could not complete[/bold yellow]",
        box=box.SIMPLE,
        show_lines=False,
        highlight=False,
    )
    table.add_column("Service",    style="cyan",   width=12)
    table.add_column("Check",      style="dim",    width=30)
    table.add_column("Resource",   width=25, overflow="fold")
    table.add_column("Error Type", style="yellow", width=15)
    table.add_column("Message",    width=50, overflow="fold")

    for err in scan_errors:
        table.add_row(
            err.service,
            err.check,
            err.resource,
            err.error_type,
            err.message,
        )

    console.print(table)
    console.print(
        "[dim]These checks could not determine security state. "
        "Add the missing IAM permissions or run with --verbose for details.[/dim]\n"
    )
