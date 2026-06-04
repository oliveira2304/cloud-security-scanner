"""
main.py — CLI entry point.

What this file does:
  Defines the `cloudscan aws` command using Typer.
  Orchestrates the scan: build client → run checks → render output.

Why Typer:
  Uses Python type hints for argument definitions. Adding a new option is
  one line — no decorator soup like raw click.

How the service filter works:
  --services s3,iam passes a comma-separated string.
  We split it and look up each service in REGISTRY.
  Unknown service names print a warning but don't crash.

How to run:
  pip install -e .
  cloudscan aws --profile default
  cloudscan aws --services s3,iam --output json
"""

from typing import Optional

import typer
from rich.console import Console

from cloudscan.aws_client import AWSClient
from cloudscan.checks import REGISTRY
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
    profile: Optional[str] = typer.Option(
        None, "--profile", "-p", help="AWS CLI profile name (from ~/.aws/credentials)."
    ),
    region: str = typer.Option(
        "us-east-1", "--region", "-r", help="AWS region to scan."
    ),
    services: Optional[str] = typer.Option(
        None,
        "--services",
        "-s",
        help="Comma-separated list of services to scan. Default: all. Example: s3,iam,ec2",
    ),
    output: str = typer.Option(
        "terminal",
        "--output",
        "-o",
        help="Output format: terminal | json | html",
    ),
    output_file: Optional[str] = typer.Option(
        None,
        "--output-file",
        "-f",
        help="File path for json/html output. Defaults to cloudscan-report.{ext}",
    ),
):
    """Scan an AWS account for security misconfigurations."""
    if ctx.invoked_subcommand is not None:
        return

    console.print("\n[bold cyan]cloudscan[/bold cyan] — AWS Security Scanner")
    console.print(f"  Profile : {profile or 'default'}")
    console.print(f"  Region  : {region}")

    # Build the AWS session
    aws_client = AWSClient(profile=profile, region=region)
    console.print(f"  Account : {aws_client.account_id}\n")

    # Resolve which checks to run
    selected = _resolve_services(services)
    console.print(f"[dim]Running checks: {', '.join(selected)}[/dim]\n")

    # Run all selected checks, aggregate findings
    all_findings = []
    for service_name in selected:
        check_fn = REGISTRY[service_name]
        with console.status(f"[cyan]Scanning {service_name.upper()}...[/cyan]"):
            try:
                findings = check_fn(aws_client)
                all_findings.extend(findings)
                console.print(
                    f"  [green]✓[/green] {service_name.upper():10} "
                    f"[dim]{len(findings)} finding(s)[/dim]"
                )
            except Exception as e:
                console.print(f"  [red]✗[/red] {service_name.upper():10} [red]Error: {e}[/red]")

    console.print()

    # Render output
    if output == "terminal":
        terminal_report.render(all_findings, account_id=aws_client.account_id)

    elif output == "json":
        from cloudscan.report import json_report
        path = output_file or "cloudscan-report.json"
        json_report.render(all_findings, path=path, account_id=aws_client.account_id)
        console.print(f"[green]JSON report saved to: {path}[/green]")

    elif output == "html":
        from cloudscan.report import html_report
        path = output_file or "cloudscan-report.html"
        html_report.render(all_findings, path=path, account_id=aws_client.account_id)
        console.print(f"[green]HTML report saved to: {path}[/green]")

    else:
        console.print(f"[red]Unknown output format: {output}. Use: terminal, json, html[/red]")
        raise typer.Exit(1)


def _resolve_services(services_arg: Optional[str]) -> list[str]:
    """Parse the --services flag and return a list of valid service names."""
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
        raise typer.Exit(1)

    return valid


def main():
    app()


if __name__ == "__main__":
    main()
