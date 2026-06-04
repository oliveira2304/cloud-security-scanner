"""
main.py — CLI entry point.

Sprint 1 additions:
  --verbose    : sets logging to DEBUG, shows boto3 warnings and API call details.
  --fail-on    : exits with code 1 if findings >= severity threshold exist.
                 Designed for GitHub Actions / CI gates.
  --min-severity: filters the DISPLAYED findings. --fail-on still checks all findings.
  --quiet      : suppresses the findings table, shows only the summary panel.

Exit codes:
  0  — scan completed, no findings at or above --fail-on threshold.
  1  — scan completed, findings found at or above --fail-on threshold.
  2  — scan failed (credentials, config error).
"""

import logging
import time
from typing import Optional

import typer
from rich.console import Console

from cloudscan.aws_client import AWSClient
from cloudscan.checks import REGISTRY
from cloudscan.models import Severity, severity_gte
from cloudscan.report import terminal as terminal_report

app = typer.Typer(
    name="cloudscan",
    help="AWS Cloud Security Scanner — detect misconfigurations in your AWS account.",
    add_completion=False,
)
console = Console()
aws_app = typer.Typer(help="Run security checks against an AWS account.")
app.add_typer(aws_app, name="aws")


@aws_app.callback(invoke_without_command=True)
def scan_aws(
    ctx: typer.Context,

    # AWS connection
    profile: Optional[str] = typer.Option(
        None, "--profile", "-p",
        help="AWS CLI profile name (from ~/.aws/credentials).",
    ),
    region: str = typer.Option(
        "us-east-1", "--region", "-r",
        help="AWS region to scan.",
    ),

    # Service selection
    services: Optional[str] = typer.Option(
        None, "--services", "-s",
        help="Comma-separated services to scan. Default: all. Example: s3,iam,ec2",
    ),

    # Output format
    output: str = typer.Option(
        "terminal", "--output", "-o",
        help="Output format: terminal | json | html",
    ),
    output_file: Optional[str] = typer.Option(
        None, "--output-file", "-f",
        help="File path for json/html output.",
    ),

    # Filtering
    min_severity: Optional[str] = typer.Option(
        None, "--min-severity",
        help="Only DISPLAY findings at this severity or above. Options: LOW, MEDIUM, HIGH, CRITICAL.",
        show_default=False,
    ),
    quiet: bool = typer.Option(
        False, "--quiet", "-q",
        help="Show only the summary panel — suppress the findings table.",
    ),

    # CI/CD gate
    fail_on: Optional[str] = typer.Option(
        None, "--fail-on",
        help=(
            "Exit with code 1 if any findings are at this severity or above. "
            "Options: LOW, MEDIUM, HIGH, CRITICAL. "
            "Designed for CI pipelines."
        ),
        show_default=False,
    ),

    # Diagnostics
    verbose: bool = typer.Option(
        False, "--verbose", "-v",
        help="Enable debug logging: show API warnings, access denied details, boto3 info.",
    ),
):
    """Scan an AWS account for security misconfigurations."""
    if ctx.invoked_subcommand is not None:
        return

    _setup_logging(verbose)

    # Validate enum-like options early — clear error before any AWS calls
    min_sev_parsed = _parse_severity(min_severity, "--min-severity") if min_severity else None
    fail_on_parsed = _parse_severity(fail_on, "--fail-on") if fail_on else None

    console.print("\n[bold cyan]cloudscan[/bold cyan] — AWS Security Scanner")
    console.print(f"  Profile  : {profile or 'default'}")
    console.print(f"  Region   : {region}")
    if fail_on_parsed:
        console.print(f"  Fail on  : [bold]{fail_on_parsed.value}[/bold] or above")
    if min_sev_parsed:
        console.print(f"  Showing  : {min_sev_parsed.value} and above")

    aws_client = AWSClient(profile=profile, region=region)
    console.print(f"  Account  : {aws_client.account_id}\n")

    selected = _resolve_services(services)
    console.print(f"[dim]Running checks: {', '.join(selected)}[/dim]\n")

    # ── Run checks ────────────────────────────────────────────────────────────
    all_findings = []
    scan_start = time.monotonic()

    for service_name in selected:
        check_fn = REGISTRY[service_name]
        with console.status(f"[cyan]Scanning {service_name.upper()}...[/cyan]"):
            try:
                findings = check_fn(aws_client)
                all_findings.extend(findings)
                console.print(
                    f"  [green]✓[/green] {service_name.upper():12} "
                    f"[dim]{len(findings)} finding(s)[/dim]"
                )
            except Exception as e:
                # Unexpected error in the check runner itself (not an AWS API error)
                console.print(f"  [red]✗[/red] {service_name.upper():12} [red]Error: {e}[/red]")
                logging.getLogger(__name__).exception("Unexpected error in check '%s'", service_name)

    scan_duration = time.monotonic() - scan_start

    if aws_client.errors:
        console.print(
            f"\n[yellow]  ⚠ {len(aws_client.errors)} check(s) could not complete "
            f"(see scan warnings below)[/yellow]"
        )

    console.print()

    # ── Render output ─────────────────────────────────────────────────────────
    if output == "terminal":
        terminal_report.render(
            all_findings,
            account_id=aws_client.account_id,
            quiet=quiet,
            min_severity=min_sev_parsed,
            scan_errors=aws_client.errors,
            scan_duration=scan_duration,
        )

    elif output == "json":
        from cloudscan.report import json_report
        path = output_file or "cloudscan-report.json"
        json_report.render(
            all_findings,
            path=path,
            account_id=aws_client.account_id,
            scan_errors=aws_client.errors,
            scan_duration=scan_duration,
        )
        console.print(f"[green]JSON report saved to: {path}[/green]")

    elif output == "html":
        from cloudscan.report import html_report
        path = output_file or "cloudscan-report.html"
        html_report.render(all_findings, path=path, account_id=aws_client.account_id)
        console.print(f"[green]HTML report saved to: {path}[/green]")

    else:
        console.print(f"[red]Unknown output format: '{output}'. Use: terminal, json, html[/red]")
        raise typer.Exit(2)

    # ── CI/CD gate ────────────────────────────────────────────────────────────
    if fail_on_parsed:
        breaching = [f for f in all_findings if severity_gte(f.severity, fail_on_parsed)]
        if breaching:
            console.print(
                f"[bold red]FAILED:[/bold red] {len(breaching)} finding(s) at "
                f"{fail_on_parsed.value} or above. Exiting with code 1.\n"
            )
            raise typer.Exit(1)
        else:
            console.print(
                f"[bold green]PASSED:[/bold green] No findings at "
                f"{fail_on_parsed.value} or above.\n"
            )


# ── Helpers ───────────────────────────────────────────────────────────────────

def _setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.WARNING
    logging.basicConfig(
        level=level,
        format="[%(levelname)s] %(name)s: %(message)s",
    )


def _parse_severity(value: str, flag_name: str) -> Severity:
    try:
        return Severity(value.upper())
    except ValueError:
        valid = ", ".join(s.value for s in Severity)
        console.print(f"[red]Invalid value for {flag_name}: '{value}'. Valid: {valid}[/red]")
        raise typer.Exit(2)


def _resolve_services(services_arg: Optional[str]) -> list[str]:
    if not services_arg:
        return list(REGISTRY.keys())

    requested = [s.strip().lower() for s in services_arg.split(",")]
    valid = []
    for name in requested:
        if name in REGISTRY:
            valid.append(name)
        else:
            console.print(f"[yellow]Warning: unknown service '{name}', skipping.[/yellow]")

    if not valid:
        console.print("[red]No valid services selected. Aborting.[/red]")
        raise typer.Exit(2)

    return valid


def main():
    app()


if __name__ == "__main__":
    main()
