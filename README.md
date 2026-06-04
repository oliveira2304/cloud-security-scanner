# ☁ cloudscan — AWS Cloud Security Scanner

> A Python CLI that scans AWS accounts for security misconfigurations and generates terminal, JSON, and HTML reports.

[![CI](https://github.com/YOUR_USERNAME/cloud-security-scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/YOUR_USERNAME/cloud-security-scanner/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/YOUR_USERNAME/cloud-security-scanner/branch/main/graph/badge.svg)](https://codecov.io/gh/YOUR_USERNAME/cloud-security-scanner)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue)](https://www.python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

---

## What it does

`cloudscan` connects to an AWS account using your existing credentials and runs security checks across S3, IAM, EC2, CloudTrail, and GuardDuty. It detects the misconfigurations most commonly found in real cloud penetration tests and security audits.

Built from scratch, **inspired by [Prowler](https://github.com/prowler-cloud/prowler) and [ScoutSuite](https://github.com/nccgroup/ScoutSuite)**, to deeply understand how cloud security scanners work rather than just using one.

**Sample output files:** [`examples/sample-output.json`](examples/sample-output.json) · [`examples/sample-report.html`](examples/sample-report.html)

---

## Demo

```
$ cloudscan aws --profile sandbox

 cloudscan — AWS Security Scanner
  Profile : sandbox
  Region  : us-east-1
  Account : 123456789012

Running checks: s3, iam, ec2, logging

  ✓ S3          4 finding(s)
  ✓ IAM         4 finding(s)
  ✓ EC2         1 finding(s)
  ✓ LOGGING     2 finding(s)

╭──────────────────────────────────────────────────────────────────────────────────────────────────────╮
│                     Cloud Security Scan Results  •  Account: 123456789012                            │
├──────────┬────────────┬──────────────────────────────┬─────────────────────────────────────┬─────────┤
│ Severity │ Service    │ Resource                     │ Title                               │Evidence │
├──────────┼────────────┼──────────────────────────────┼─────────────────────────────────────┼─────────┤
│ CRITICAL │ S3         │ acme-app-assets-prod          │ S3 Block Public Access config…      │ Public… │
│ CRITICAL │ IAM        │ DevOpsFullAccess              │ IAM policy grants full admin…       │ Action… │
│ CRITICAL │ EC2        │ sg-0a1b2c3d (web-tier-sg)    │ Security Group exposes SSH port 22… │ 0.0.0.… │
│ CRITICAL │ CloudTrail │ account/123456789012          │ CloudTrail is not enabled           │ descri… │
│   HIGH   │ S3         │ acme-app-assets-prod          │ S3 bucket encryption not enabled    │ GetBuc… │
│   HIGH   │ IAM        │ deploy-user                  │ IAM user has no MFA device          │ ListMF… │
│   HIGH   │ IAM        │ deploy-user                  │ IAM access key not rotated…143 days │ AKIA0… │
│   HIGH   │ GuardDuty  │ account/123456789012          │ GuardDuty is not enabled            │ list_d… │
│  MEDIUM  │ S3         │ acme-backups-2024             │ S3 bucket versioning not enabled    │ Versio… │
╰──────────┴────────────┴──────────────────────────────┴─────────────────────────────────────┴─────────╯

╭─ Scan Summary ─────────────────────────╮
│ Account: 123456789012                  │
│ Total findings: 11                     │
│                                        │
│   CRITICAL  4                          │
│      HIGH   5                          │
│    MEDIUM   2                          │
│       LOW   0                          │
╰────────────────────────────────────────╯
```

---

## Checks

| Service | ID | Severity |
|---|---|:---:|
| **S3** | Block Public Access disabled or missing | `CRITICAL` |
| **S3** | Server-side encryption not configured | `HIGH` |
| **S3** | Versioning disabled | `MEDIUM` |
| **IAM** | User without MFA device | `HIGH` |
| **IAM** | Access key not rotated in 90+ days | `HIGH` |
| **IAM** | Customer-managed policy with `Action: "*"` + `Resource: "*"` | `CRITICAL` |
| **EC2** | Security Group with SSH (22) open to `0.0.0.0/0` | `CRITICAL` |
| **EC2** | Security Group with RDP (3389) open to `0.0.0.0/0` | `CRITICAL` |
| **EC2** | Database ports (3306, 5432, 6379, 9200) open to world | `HIGH` |
| **EC2** | Security Group allows all traffic from internet | `CRITICAL` |
| **CloudTrail** | No trail configured in region | `CRITICAL` |
| **CloudTrail** | Trail exists but logging is disabled | `CRITICAL` |
| **GuardDuty** | Detector not enabled | `HIGH` |
| **GuardDuty** | Detector suspended | `HIGH` |

---

## Installation

**Requirements:** Python 3.11+, AWS credentials configured (`aws configure` or environment variables).

```bash
git clone https://github.com/YOUR_USERNAME/cloud-security-scanner.git
cd cloud-security-scanner

# Create virtual environment (recommended)
python -m venv .venv
source .venv/bin/activate        # Linux/macOS
.venv\Scripts\activate           # Windows

pip install -e .
```

---

## Usage

```bash
# Scan using default AWS profile
cloudscan aws

# Scan with a named profile
cloudscan aws --profile sandbox

# Scan a specific region
cloudscan aws --region eu-west-1

# Scan specific services only
cloudscan aws --services s3,iam

# Export findings as JSON
cloudscan aws --output json --output-file results.json

# Generate an HTML report
cloudscan aws --output html --output-file report.html

# Combine options
cloudscan aws --profile sandbox --region eu-west-1 --services s3,iam,ec2 --output html
```

### Output formats

| Format | Command | Use case |
|--------|---------|----------|
| Terminal | `--output terminal` (default) | Interactive use, quick checks |
| JSON | `--output json` | Automation, diffing, SIEM ingestion |
| HTML | `--output html` | Reports to share with teams |

Sample outputs: [`sample-output.json`](examples/sample-output.json) · [`sample-report.html`](examples/sample-report.html)

---

## Architecture

```
cloudscan/
├── main.py               CLI entry point (Typer)
├── models.py             Finding dataclass + Severity enum
├── aws_client.py         boto3 session wrapper
├── checks/
│   ├── __init__.py       REGISTRY: maps service name → run()
│   ├── s3.py             S3 checks
│   ├── iam.py            IAM checks
│   ├── ec2.py            EC2 / Security Group checks
│   └── logging_checks.py CloudTrail + GuardDuty
└── report/
    ├── terminal.py        Rich table + summary panel
    ├── json_report.py     Structured JSON with metadata envelope
    └── html_report.py     Jinja2 → self-contained HTML
```

**Key design decisions:**

- **Every check has signature `run(client) → List[Finding]`** — reporters are completely decoupled from AWS logic. Adding a new service means one new file and one line in `REGISTRY`.
- **`Finding` is a dataclass, not a dict** — type-safe throughout, but serialises cleanly to JSON via `.to_dict()`.
- **`AWSClient` wraps boto3** — credentials and region configured in one place; tests swap in mocked sessions without touching check code.
- **Fail fast on credentials** — `AWSClient.__init__` calls `sts:GetCallerIdentity` immediately, not mid-scan.

---

## Running tests

Tests use [moto](https://github.com/getmoto/moto) to mock AWS — no real account or credentials needed.

```bash
pip install -e ".[dev]"

# Run all tests
pytest

# With coverage
pytest --cov=cloudscan --cov-report=term-missing
```

The test suite covers each check function in isolation: creating the specific misconfiguration, calling the check, and asserting on finding ID and severity.

---

## Terraform vulnerable lab

The `terraform-lab/insecure-aws-lab/` directory provisions intentionally misconfigured AWS resources for end-to-end testing.

**Resources created:**
- S3 bucket with Block Public Access disabled, no encryption, no versioning
- IAM user without MFA + access key + wildcard `Action:*` policy
- Security Group with SSH (22) and MySQL (3306) open to `0.0.0.0/0`

```bash
cd terraform-lab/insecure-aws-lab
terraform init
terraform apply     # ⚠ use a sandbox account only

# Scan the environment — should surface 8+ findings
cloudscan aws --profile sandbox

# Clean up all resources
terraform destroy
```

> **Warning:** Only run this in a dedicated AWS sandbox account. It intentionally creates public resources.

---

## Required AWS permissions

`cloudscan` only needs read-only access. Example least-privilege policy:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": [
      "s3:ListAllMyBuckets",
      "s3:GetBucketPublicAccessBlock",
      "s3:GetBucketEncryption",
      "s3:GetBucketVersioning",
      "iam:ListUsers",
      "iam:ListMFADevices",
      "iam:ListAccessKeys",
      "iam:ListPolicies",
      "iam:GetPolicyVersion",
      "ec2:DescribeSecurityGroups",
      "cloudtrail:DescribeTrails",
      "cloudtrail:GetTrailStatus",
      "guardduty:ListDetectors",
      "guardduty:GetDetector",
      "sts:GetCallerIdentity"
    ],
    "Resource": "*"
  }]
}
```

---

## Stack

| Layer | Technology |
|-------|-----------|
| Language | Python 3.11+ |
| CLI framework | [Typer](https://typer.tiangolo.com/) |
| Terminal UI | [Rich](https://github.com/Textualize/rich) |
| HTML reports | [Jinja2](https://jinja.palletsprojects.com/) |
| AWS SDK | [boto3](https://boto3.amazonaws.com/v1/documentation/api/latest/index.html) |
| Testing | [pytest](https://pytest.org) + [moto](https://github.com/getmoto/moto) |
| Linter | [ruff](https://github.com/astral-sh/ruff) |
| Infrastructure | [Terraform](https://www.terraform.io/) ≥ 1.6 |
| CI | GitHub Actions |

---

## Roadmap

- [ ] Multi-region scanning (`--all-regions`)
- [ ] Assume-role support for cross-account scanning
- [ ] RDS: public access, encryption at rest, deletion protection
- [ ] Lambda: function URLs with public auth, environment variable secrets
- [ ] AWS Config rules status check
- [ ] SARIF output format (integrates with GitHub Security tab)
- [ ] Severity filtering (`--min-severity HIGH`)
- [ ] JSON diff between two scan results

---

## License

MIT
