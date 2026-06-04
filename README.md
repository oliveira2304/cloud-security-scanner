# cloudscan - AWS Cloud Security Scanner

> A Python CLI that scans AWS accounts for security misconfigurations and generates terminal, JSON, and HTML reports.

[![CI](https://github.com/oliveira2304/cloud-security-scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/oliveira2304/cloud-security-scanner/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/oliveira2304/cloud-security-scanner/branch/main/graph/badge.svg)](https://codecov.io/gh/oliveira2304/cloud-security-scanner)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue)](https://www.python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

---

## What it does

`cloudscan` connects to an AWS account using your existing credentials and runs security checks across S3, IAM, EC2, CloudTrail, and GuardDuty. It detects the misconfigurations most commonly found in real cloud penetration tests and security audits.

Built from scratch, **inspired by [Prowler](https://github.com/prowler-cloud/prowler) and [ScoutSuite](https://github.com/nccgroup/ScoutSuite)**, to deeply understand how cloud security scanners work rather than just using one.

**Sample output files:** [`examples/sample-output.json`](examples/sample-output.json) | [`examples/sample-report.html`](examples/sample-report.html)

---

## Checks

| Service | Check | Severity |
|---|---|:---:|
| **S3** | Block Public Access disabled or missing | `CRITICAL` |
| **S3** | Server-side encryption not configured | `HIGH` |
| **S3** | Versioning disabled | `MEDIUM` |
| **IAM** | Root account has active access keys | `CRITICAL` |
| **IAM** | Root account has no MFA enabled | `CRITICAL` |
| **IAM** | Root account used in last 30 days | `HIGH` |
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
git clone https://github.com/oliveira2304/cloud-security-scanner.git
cd cloud-security-scanner

python -m venv .venv
source .venv/bin/activate        # Linux/macOS
.venv\Scripts\activate           # Windows

pip install -e .
```

---

## Usage

### Basic scan

```bash
# Scan using the default AWS profile
cloudscan aws

# Scan with a named profile and specific region
cloudscan aws --profile sandbox --region eu-west-1

# Scan specific services only
cloudscan aws --services s3,iam
```

### Output formats

```bash
# Terminal output (default)
cloudscan aws

# Export as JSON
cloudscan aws --output json --output-file results.json

# Generate an HTML report
cloudscan aws --output html --output-file report.html
```

### Filtering output

```bash
# Show only HIGH and CRITICAL findings
cloudscan aws --min-severity HIGH

# Show only the summary panel (no findings table)
cloudscan aws --quiet

# Combine: quiet summary of critical findings only
cloudscan aws --min-severity CRITICAL --quiet
```

### CI/CD pipeline integration

`--fail-on` exits with **code 1** if any findings are at or above the threshold.
This makes `cloudscan` a security gate in GitHub Actions, GitLab CI, or Jenkins.

```bash
# Fail the pipeline if any CRITICAL findings are found
cloudscan aws --fail-on CRITICAL

# Fail on HIGH or above
cloudscan aws --fail-on HIGH

# Full CI usage: specific services, exit code, JSON artifact
cloudscan aws --services s3,iam,ec2 --fail-on CRITICAL --output json --output-file scan.json
```

**GitHub Actions example:**

```yaml
- name: Run cloudscan security check
  run: cloudscan aws --fail-on CRITICAL --output json --output-file scan.json

- name: Upload scan results
  uses: actions/upload-artifact@v4
  with:
    name: cloudscan-results
    path: scan.json
  if: always()
```

### Debugging and permissions

```bash
# Show API warnings, AccessDenied details, and boto3 debug info
cloudscan aws --verbose

# Example output with --verbose when a permission is missing:
# [WARNING] cloudscan.aws_client: ACCESS DENIED — S3/_check_public_access on resource 'my-bucket'.
# Add the required IAM permission to the scanning role.
```

When a check fails due to missing permissions, `cloudscan` **never silently returns "no findings"**.
It shows a dedicated "Scan Warnings" section so you always know when results may be incomplete.

### Exit codes

| Code | Meaning |
|------|---------|
| `0` | Scan completed, no findings at or above `--fail-on` threshold |
| `1` | Scan completed, findings found at or above `--fail-on` threshold |
| `2` | Scan failed (bad credentials, invalid arguments) |

---

## Demo output

```
cloudscan - AWS Security Scanner
  Profile  : sandbox
  Region   : us-east-1
  Fail on  : CRITICAL or above
  Account  : 123456789012

Running checks: s3, iam, ec2, logging

  + S3           4 finding(s)
  + IAM          5 finding(s)
  + EC2          1 finding(s)
  + LOGGING      2 finding(s)

+----------+------------+------------------------------+-------------------------------------+
| Severity | Service    | Resource                     | Title                               |
+----------+------------+------------------------------+-------------------------------------+
| CRITICAL | IAM        | root                         | Root account has no MFA enabled     |
| CRITICAL | IAM        | root                         | Root account has active access keys |
| CRITICAL | S3         | acme-app-assets-prod         | S3 Block Public Access config...    |
| CRITICAL | EC2        | sg-0a1b2c3d (web-tier-sg)   | Security Group exposes SSH port 22  |
| CRITICAL | CloudTrail | account/123456789012         | CloudTrail is not enabled           |
|   HIGH   | IAM        | root                         | Root account was used 3 day(s) ago  |
|   HIGH   | IAM        | deploy-user                  | IAM user has no MFA device          |
|   HIGH   | S3         | acme-app-assets-prod         | S3 bucket encryption not enabled    |
|   HIGH   | GuardDuty  | account/123456789012         | GuardDuty is not enabled            |
|  MEDIUM  | S3         | acme-backups-2024            | S3 bucket versioning not enabled    |
+----------+------------+------------------------------+-------------------------------------+

 Scan Summary
  Account:        123456789012
  Total findings: 12

  CRITICAL  5
      HIGH  4
    MEDIUM  1
       LOW  0

  Scan completed in 3.2s

FAILED: 5 finding(s) at CRITICAL or above. Exiting with code 1.
```

---

## Architecture

```
cloudscan/
├── main.py               CLI entry point (Typer) — orchestration, flags, exit codes
├── models.py             Finding + ScanError dataclasses, Severity enum, severity_gte()
├── aws_client.py         boto3 session wrapper + error collector (record_error)
├── checks/
│   ├── __init__.py       REGISTRY: maps service name to run()
│   ├── s3.py             S3 checks
│   ├── iam.py            IAM checks (incl. root account)
│   ├── ec2.py            EC2 / Security Group checks
│   └── logging_checks.py CloudTrail + GuardDuty
└── report/
    ├── terminal.py        Rich table + summary + scan warnings panel
    ├── json_report.py     Structured JSON with metadata envelope
    └── html_report.py     Jinja2 self-contained HTML report
```

**Key design decisions:**

- **`Finding` vs `ScanError`** — Security issues and scanner failures are separate types. `0 findings` never means "scan failed silently". Incomplete scans surface a distinct "Scan Warnings" section.
- **`record_error()` on AWSClient** — All checks delegate error handling to the client. Each check function raises `ClientError` freely; `run()` catches it and calls `client.record_error()`. This is testable and centralized.
- **`--fail-on` evaluates all findings** — `--min-severity` only affects display. The CI gate always runs against the full finding list, so hidden lower-severity findings don't mask failures.
- **Cached `account_id`** — The original implementation called `sts:GetCallerIdentity` on every property access. Now it's cached at session init.

---

## Running tests

Tests use [moto](https://github.com/getmoto/moto) to mock AWS — **no real account or credentials needed**.

```bash
pip install -e ".[dev]"

# Run all tests
pytest

# With coverage report
pytest --cov=cloudscan --cov-report=term-missing

# Run a specific test file
pytest tests/test_iam.py -v
```

**Test coverage includes:**
- S3: public access (missing config, partial, fully enabled), encryption, versioning
- IAM: root MFA, root access keys, user MFA, key rotation, wildcard policies
- EC2: SSH/RDP/DB ports open, all-traffic rule, restricted access (no finding)
- Models: severity comparison logic for `--fail-on` and `--min-severity`
- Error handling: AccessDenied is recorded, never swallowed

---

## Terraform vulnerable lab

`terraform-lab/insecure-aws-lab/` provisions intentionally misconfigured resources for end-to-end testing.

```bash
cd terraform-lab/insecure-aws-lab
terraform init
terraform apply     # sandbox account only

cloudscan aws --profile sandbox --fail-on CRITICAL

terraform destroy
```

> **Warning:** Only run this in a dedicated AWS sandbox account.

---

## Required AWS permissions

`cloudscan` only needs read-only access:

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
      "iam:GetAccountSummary",
      "iam:GenerateCredentialReport",
      "iam:GetCredentialReport",
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
| Infrastructure | [Terraform](https://www.terraform.io/) >= 1.6 |
| CI | GitHub Actions |

---

## Roadmap

- [ ] Compliance framework mapping (CIS AWS Benchmark, NIST 800-53)
- [ ] SARIF output (GitHub Security tab integration)
- [ ] Multi-region scanning (`--all-regions`)
- [ ] Assume-role support for cross-account scanning
- [ ] RDS: public access, encryption, deletion protection
- [ ] Lambda: public function URLs, environment variable secrets
- [ ] Severity filtering (`--min-severity`) — done in v0.2
- [ ] CI exit codes (`--fail-on`) — done in v0.2

---

## License

MIT
