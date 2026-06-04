# cloudscan Vulnerable Lab

A Terraform environment that creates intentionally misconfigured AWS resources
for end-to-end testing of `cloudscan`.

**Only run this in a dedicated sandbox AWS account.**

---

## What it creates

| Resource | Misconfiguration | cloudscan finding |
|---|---|---|
| S3 bucket | Block Public Access disabled, no encryption | `S3_PUBLIC_ACCESS_BLOCK_DISABLED`, `S3_ENCRYPTION_DISABLED`, `S3_VERSIONING_DISABLED` |
| IAM user | No MFA, active access key | `IAM_USER_NO_MFA` |
| IAM policy | `Action: "*", Resource: "*"` | `IAM_POLICY_WILDCARD_ADMIN` |
| Security Group | SSH (22) + MySQL (3306) open to `0.0.0.0/0` | `EC2_SG_SSH_OPEN`, `EC2_SG_MYSQL_OPEN` |
| RDS MySQL | Public, no encryption, no deletion protection, single-AZ | `RDS_INSTANCE_PUBLIC`, `RDS_ENCRYPTION_DISABLED`, `RDS_DELETION_PROTECTION_OFF`, `RDS_MULTI_AZ_DISABLED` |
| Lambda function | Function URL with `AuthType=NONE`, password env var | `LAMBDA_PUBLIC_URL`, `LAMBDA_ENV_SECRET_EXPOSURE` |

Expected total: **13+ findings** (CRITICAL, HIGH, MEDIUM, LOW).

---

## Prerequisites

- [Terraform](https://www.terraform.io/) >= 1.6
- AWS credentials configured for a sandbox account
- `cloudscan` installed (`pip install -e .` from project root)

---

## Usage

```bash
cd terraform-lab/insecure-aws-lab

# 1. Initialise providers
terraform init

# 2. Preview what will be created
terraform plan

# 3. Create the vulnerable environment (sandbox account only!)
terraform apply

# 4. Scan it — should find 13+ misconfigurations
cloudscan aws --profile sandbox --region us-east-1

# 5. Try different output formats
cloudscan aws --profile sandbox --output html --output-file lab-report.html
cloudscan aws --profile sandbox --output json --output-file lab-findings.json

# 6. Test the CI gate
cloudscan aws --profile sandbox --fail-on CRITICAL

# 7. Destroy everything when done
terraform destroy
```

---

## Expected cloudscan output

```
  ✓ S3            3 finding(s)
  ✓ IAM           3 finding(s)    (+ root checks from the account)
  ✓ EC2           2 finding(s)
  ✓ RDS           4 finding(s)
  ✓ LAMBDA        2 finding(s)
  ✓ LOGGING       2 finding(s)    (if CloudTrail/GuardDuty not enabled in sandbox)

 Scan Summary
  Total findings: 16+
  CRITICAL  7
  HIGH      5
  MEDIUM    2
  LOW       2
```

---

## Why this is useful for learning

Each finding maps to a real-world attack scenario:

- **`RDS_INSTANCE_PUBLIC`** — In 2020, the Capital One breach involved a public-facing
  EC2 instance. Public RDS instances are the same risk but for databases directly.
- **`LAMBDA_PUBLIC_URL`** — Any public endpoint without authentication can be used for
  DDoS, SSRF attacks, or to exfiltrate data if the function has overly broad IAM permissions.
- **`IAM_POLICY_WILDCARD_ADMIN`** — One leaked key from a user with this policy = full
  account compromise.
- **`EC2_SG_SSH_OPEN`** — Still the #1 finding in AWS penetration tests (2024 Verizon DBIR).

---

## Cleanup verification

After `terraform destroy`, verify no resources remain:

```bash
aws s3 ls | grep cloudscan-lab
aws iam list-users | grep cloudscan-lab
aws ec2 describe-security-groups --filters Name=tag:Purpose,Values=cloudscan-lab
aws rds describe-db-instances | grep cloudscan-lab
aws lambda list-functions | grep cloudscan-lab
```
