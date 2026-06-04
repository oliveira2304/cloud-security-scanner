"""
demo.py — Run cloudscan against a simulated vulnerable AWS account.

No AWS credentials needed — uses moto to mock all AWS API calls.
Creates intentionally misconfigured resources so you can see real findings.

Usage:
    python demo.py                  # terminal output
    python demo.py --output json    # JSON report
    python demo.py --output html    # HTML report
    python demo.py --output sarif   # SARIF report
"""

import json
import os
import sys
import argparse

# Force UTF-8 on Windows (fixes ✓ / ✗ in PowerShell and cmd.exe)
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

# Inject fake credentials before anything else touches boto3
os.environ.update({
    "AWS_ACCESS_KEY_ID":     "demo-key",
    "AWS_SECRET_ACCESS_KEY": "demo-secret",
    "AWS_DEFAULT_REGION":    "us-east-1",
})

import boto3
from moto import mock_aws


@mock_aws
def main():
    parser = argparse.ArgumentParser(description="cloudscan demo (no real AWS needed)")
    parser.add_argument("--output", default="terminal",
                        choices=["terminal", "json", "html", "sarif"])
    parser.add_argument("--output-file", default=None)
    args = parser.parse_args()

    _setup_vulnerable_account()
    _run_scan(args.output, args.output_file)


def _setup_vulnerable_account():
    """Create misconfigured resources in the moto mock environment."""
    from rich.console import Console
    console = Console()
    console.print("\n[dim]Setting up simulated vulnerable AWS account...[/dim]")

    s3  = boto3.client("s3",  region_name="us-east-1")
    iam = boto3.client("iam", region_name="us-east-1")
    ec2 = boto3.client("ec2", region_name="us-east-1")

    # ── S3: three buckets with different issues ───────────────────────────────
    # Bucket 1 — no public access block (CRITICAL), no encryption (HIGH), no versioning (MEDIUM)
    s3.create_bucket(Bucket="acme-app-assets-prod")

    # Bucket 2 — partial block public access (CRITICAL), no encryption (HIGH)
    s3.create_bucket(Bucket="acme-backups-2024")
    s3.put_public_access_block(
        Bucket="acme-backups-2024",
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True, "IgnorePublicAcls": True,
            "BlockPublicPolicy": False, "RestrictPublicBuckets": False,
        },
    )

    # Bucket 3 — fully secure (no findings expected)
    s3.create_bucket(Bucket="acme-secure-logs")
    s3.put_public_access_block(
        Bucket="acme-secure-logs",
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True, "IgnorePublicAcls": True,
            "BlockPublicPolicy": True, "RestrictPublicBuckets": True,
        },
    )
    s3.put_bucket_encryption(
        Bucket="acme-secure-logs",
        ServerSideEncryptionConfiguration={
            "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]
        },
    )
    s3.put_bucket_versioning(
        Bucket="acme-secure-logs",
        VersioningConfiguration={"Status": "Enabled"},
    )

    # ── IAM: two users without MFA, one wildcard policy ───────────────────────
    for username in ("deploy-user", "ci-bot"):
        iam.create_user(UserName=username)
        iam.create_access_key(UserName=username)   # active keys

    iam.create_policy(
        PolicyName="DevOpsFullAccess",
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
        }),
    )

    # ── EC2: Security Group with SSH + MySQL open to the world ────────────────
    sg = ec2.create_security_group(GroupName="web-tier-sg", Description="Web tier")
    ec2.authorize_security_group_ingress(
        GroupId=sg["GroupId"],
        IpPermissions=[
            {
                "IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
                "IpRanges": [{"CidrIp": "0.0.0.0/0", "Description": "SSH open to world"}],
            },
            {
                "IpProtocol": "tcp", "FromPort": 3306, "ToPort": 3306,
                "IpRanges": [{"CidrIp": "0.0.0.0/0", "Description": "MySQL open to world"}],
            },
            {
                "IpProtocol": "tcp", "FromPort": 443, "ToPort": 443,
                "IpRanges": [{"CidrIp": "0.0.0.0/0", "Description": "HTTPS - fine"}],
            },
        ],
    )

    console.print("[dim]Vulnerable account ready.[/dim]\n")


def _run_scan(output_format: str, output_file: str | None):
    """Run the actual cloudscan checks against the mocked environment."""
    import time
    from rich.console import Console
    from cloudscan.aws_client import AWSClient
    from cloudscan.checks import REGISTRY
    from cloudscan.models import severity_gte, Severity
    from cloudscan.report import terminal as terminal_report

    console = Console()

    console.print("[bold cyan]cloudscan[/bold cyan] — AWS Security Scanner")
    console.print("  Profile  : demo (moto mock)")
    console.print("  Region   : us-east-1")

    client = AWSClient(profile=None, region="us-east-1")
    console.print(f"  Account  : {client.account_id}")
    console.print(f"  Mode     : simulated vulnerable account\n")

    services = list(REGISTRY.keys())
    console.print(f"[dim]Services : {', '.join(services)}[/dim]\n")

    all_findings = []
    scan_start = time.monotonic()

    for service_name in services:
        check_fn = REGISTRY[service_name]
        with console.status(f"[cyan]Scanning {service_name.upper()}...[/cyan]"):
            try:
                findings = check_fn(client)
                for f in findings:
                    if f.region is None:
                        f.region = "us-east-1"
                all_findings.extend(findings)
                console.print(
                    f"  [green]✓[/green] {service_name.upper():12} "
                    f"[dim]{len(findings)} finding(s)[/dim]"
                )
            except Exception as e:
                console.print(f"  [red]✗[/red] {service_name.upper():12} [red]{e}[/red]")

    scan_duration = time.monotonic() - scan_start

    if client.errors:
        console.print(
            f"\n[yellow]  ⚠ {len(client.errors)} check(s) incomplete[/yellow]"
        )
    console.print()

    if output_format == "terminal":
        terminal_report.render(
            all_findings,
            account_id=client.account_id,
            scan_errors=client.errors,
            scan_duration=scan_duration,
        )

    elif output_format == "json":
        from cloudscan.report import json_report
        path = output_file or "demo-report.json"
        json_report.render(all_findings, path=path, account_id=client.account_id,
                           scan_errors=client.errors, scan_duration=scan_duration)
        console.print(f"[green]JSON saved to:[/green] {path}")

    elif output_format == "html":
        from cloudscan.report import html_report
        path = output_file or "demo-report.html"
        html_report.render(all_findings, path=path, account_id=client.account_id)
        console.print(f"[green]HTML saved to:[/green] {path}")
        import subprocess, sys
        subprocess.Popen(["cmd", "/c", "start", path], shell=False)

    elif output_format == "sarif":
        from cloudscan.report import sarif_report
        path = output_file or "demo-report.sarif"
        sarif_report.render(all_findings, path=path, account_id=client.account_id)
        console.print(f"[green]SARIF saved to:[/green] {path}")


if __name__ == "__main__":
    main()
