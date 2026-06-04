"""
main.py — CLI entry point.

Sprint 3: Added --all-regions and multi-region support.
          --region now accepts a comma-separated list.

Exit codes:
  0  — scan completed, no findings at or above --fail-on threshold.
  1  — scan completed, findings found at or above --fail-on threshold.
  2  — scan failed (credentials, config error, bad arguments).
"""

import logging
import time
from typing import Optional

import typer
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn

from cloudscan.aws_client import AWSClient
from cloudscan.checks import REGISTRY, run_all_regions
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
        help="Region to scan. Accepts comma-separated list: us-east-1,eu-west-1",
    ),
    all_regions: bool = typer.Option(
        False, "--all-regions",
        help="Scan all regions enabled in the account. Overrides --region.",
    ),

    # Service selection
    services: Optional[str] = typer.Option(
        None, "--services", "-s",
        help="Comma-separated services to scan. Default: all. Example: s3,iam,ec2,rds,lambda",
    ),

    # Output
    output: str = typer.Option(
        "terminal", "--output", "-o",
        help="Output format: terminal | json | html | sarif",
    ),
    output_file: Optional[str] = typer.Option(
        None, "--output-file", "-f",
        help="File path for json/html/sarif output.",
    ),

    # Filtering
    min_severity: Optional[str] = typer.Option(
        None, "--min-severity",
        help="Only display findings >= this severity: LOW, MEDIUM, HIGH, CRITICAL.",
        show_default=False,
    ),
    quiet: bool = typer.Option(
        False, "--quiet", "-q",
        help="Show only the summary panel — suppress findings table.",
    ),

    # CI/CD gate
    fail_on: Optional[str] = typer.Option(
        None, "--fail-on",
        help="Exit code 1 if findings >= this severity: LOW, MEDIUM, HIGH, CRITICAL.",
        show_default=False,
    ),

    # Diagnostics
    verbose: bool = typer.Option(
        False, "--verbose", "-v",
        help="Enable debug logging: API warnings, AccessDenied details.",
    ),
):
    """Scan an AWS account for security misconfigurations."""
    if ctx.invoked_subcommand is not None:
        return

    _setup_logging(verbose)

    min_sev_parsed = _parse_severity(min_severity, "--min-severity") if min_severity else None
    fail_on_parsed = _parse_severity(fail_on, "--fail-on") if fail_on else None

    # ── Authenticate ──────────────────────────────────────────────────────────
    # Use the first region for session init. for_region() handles the rest.
    primary_region = region.split(",")[0].strip()
    aws_client = AWSClient(profile=profile, region=primary_region)

    # ── Resolve regions ───────────────────────────────────────────────────────
    if all_regions:
        regions = aws_client.list_enabled_regions()
    else:
        regions = [r.strip() for r in region.split(",") if r.strip()]

    multi = len(regions) > 1

    # ── Print header ──────────────────────────────────────────────────────────
    console.print("\n[bold cyan]cloudscan[/bold cyan] — AWS Security Scanner")
    console.print(f"  Profile  : {profile or 'default'}")
    if multi:
        console.print(f"  Regions  : {', '.join(regions[:5])}{'...' if len(regions) > 5 else ''} ({len(regions)} total)")
    else:
        console.print(f"  Region   : {regions[0]}")
    if fail_on_parsed:
        console.print(f"  Fail on  : [bold]{fail_on_parsed.value}[/bold] or above")
    if min_sev_parsed:
        console.print(f"  Showing  : {min_sev_parsed.value} and above")
    console.print(f"  Account  : {aws_client.account_id}\n")

    selected = _resolve_services(services)
    console.print(f"[dim]Services : {', '.join(selected)}[/dim]")
    if multi:
        console.print(f"[dim]Mode     : multi-region ({len(regions)} regions × {len(selected)} services)[/dim]")
    console.print()

    # ── Run checks ────────────────────────────────────────────────────────────
    all_findings = []
    scan_start = time.monotonic()

    if multi:
        all_findings = _run_multi_region(aws_client, selected, regions)
    else:
        all_findings = _run_single_region(aws_client, selected)

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
            multi_region=multi,
        )

    elif output == "json":
        from cloudscan.report import json_report
        path = output_file or "cloudscan-report.json"
        json_report.render(
            all_findings, path=path,
            account_id=aws_client.account_id,
            scan_errors=aws_client.errors,
            scan_duration=scan_duration,
        )
        console.print(f"[green]JSON report saved to:[/green] {path}")

    elif output == "html":
        from cloudscan.report import html_report
        path = output_file or "cloudscan-report.html"
        html_report.render(all_findings, path=path, account_id=aws_client.account_id)
        console.print(f"[green]HTML report saved to:[/green] {path}")

    elif output == "sarif":
        from cloudscan.report import sarif_report
        path = output_file or "cloudscan-report.sarif"
        sarif_report.render(all_findings, path=path, account_id=aws_client.account_id)
        console.print(f"[green]SARIF report saved to:[/green] {path}")

    else:
        console.print(f"[red]Unknown format: '{output}'. Use: terminal, json, html, sarif[/red]")
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
        console.print(
            f"[bold green]PASSED:[/bold green] No findings at "
            f"{fail_on_parsed.value} or above.\n"
        )


# ── Scan runners ──────────────────────────────────────────────────────────────

def _run_single_region(aws_client: AWSClient, selected: list[str]) -> list:
    all_findings = []
    for service_name in selected:
        check_fn = REGISTRY[service_name]
        with console.status(f"[cyan]Scanning {service_name.upper()}...[/cyan]"):
            try:
                findings = check_fn(aws_client)
                for f in findings:
                    if f.region is None:
                        f.region = aws_client.region
                all_findings.extend(findings)
                console.print(
                    f"  [green]✓[/green] {service_name.upper():12} "
                    f"[dim]{len(findings)} finding(s)[/dim]"
                )
            except Exception as e:
                console.print(f"  [red]✗[/red] {service_name.upper():12} [red]Error: {e}[/red]")
                logging.getLogger(__name__).exception("Unexpected error in '%s'", service_name)
    return all_findings


def _run_multi_region(aws_client: AWSClient, selected: list[str], regions: list[str]) -> list:
    """Run checks across multiple regions with a Rich progress bar."""
    total_tasks = sum(
        len(regions) if svc not in {"iam"} else 1
        for svc in selected
    )
    completed = [0]

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        console=console,
        transient=True,
    ) as progress:
        task = progress.add_task(
            f"[cyan]Scanning {len(regions)} regions...",
            total=total_tasks,
        )

        def on_progress(region, service_name, n_findings):
            completed[0] += 1
            progress.update(
                task,
                advance=1,
                description=f"[cyan]{service_name.upper()} / {region} → {n_findings} finding(s)",
            )

        findings = run_all_regions(
            aws_client, selected, regions, progress_callback=on_progress
        )

    # Print per-region summary
    by_region: dict[str, int] = {}
    for f in findings:
        r = f.region or "unknown"
        by_region[r] = by_region.get(r, 0) + 1

    for r in sorted(by_region):
        console.print(f"  [green]✓[/green] {r:25} [dim]{by_region[r]} finding(s)[/dim]")

    return findings


# ── Helpers ───────────────────────────────────────────────────────────────────

def _setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.WARNING
    logging.basicConfig(level=level, format="[%(levelname)s] %(name)s: %(message)s")


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
