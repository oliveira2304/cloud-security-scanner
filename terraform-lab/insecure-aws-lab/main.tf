/*
  terraform-lab/insecure-aws-lab/main.tf

  Purpose:
    Creates a deliberately insecure AWS environment to test cloudscan findings.
    Run this in a dedicated sandbox/test AWS account — NEVER in production.

  Resources created (all intentionally misconfigured):
    - S3 bucket with public access and no encryption
    - IAM user with no MFA and an old access key
    - Security Group with SSH open to 0.0.0.0/0
    - CloudTrail disabled (just don't create it)

  After applying:
    cloudscan aws --profile sandbox --region us-east-1

  Destroy when done:
    terraform destroy
*/

terraform {
  required_version = ">= 1.6"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.region
}

variable "region" {
  default = "us-east-1"
}

# ── S3: public bucket, no encryption, no versioning ─────────────────────────

resource "aws_s3_bucket" "vulnerable" {
  bucket        = "cloudscan-test-vulnerable-${random_id.suffix.hex}"
  force_destroy = true

  tags = { Purpose = "cloudscan-test" }
}

# Deliberately disable block public access
resource "aws_s3_bucket_public_access_block" "vulnerable" {
  bucket = aws_s3_bucket.vulnerable.id

  block_public_acls       = false
  ignore_public_acls      = false
  block_public_policy     = false
  restrict_public_buckets = false
}

# No encryption configured (absence of aws_s3_bucket_server_side_encryption_configuration)
# No versioning configured (absence of aws_s3_bucket_versioning)

resource "random_id" "suffix" {
  byte_length = 4
}

# ── IAM: user without MFA, overly permissive policy ─────────────────────────

resource "aws_iam_user" "no_mfa_user" {
  name = "cloudscan-test-no-mfa-user"
  tags = { Purpose = "cloudscan-test" }
}

resource "aws_iam_access_key" "no_mfa_user" {
  user = aws_iam_user.no_mfa_user.name
}

# Wildcard policy — Action:* Resource:*
resource "aws_iam_policy" "wildcard_admin" {
  name        = "cloudscan-test-wildcard-policy"
  description = "Test policy with wildcard permissions (intentionally insecure)"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "*"
      Resource = "*"
    }]
  })
}

# ── EC2: Security Group with SSH open to the world ───────────────────────────

resource "aws_security_group" "ssh_open" {
  name        = "cloudscan-test-ssh-open"
  description = "Intentionally insecure SG for cloudscan testing"

  ingress {
    description = "SSH open to world (INSECURE - test only)"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "MySQL open to world (INSECURE - test only)"
    from_port   = 3306
    to_port     = 3306
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Purpose = "cloudscan-test" }
}

# ── Outputs ──────────────────────────────────────────────────────────────────

output "vulnerable_bucket_name" {
  value = aws_s3_bucket.vulnerable.bucket
}

output "test_user_name" {
  value = aws_iam_user.no_mfa_user.name
}

output "insecure_sg_id" {
  value = aws_security_group.ssh_open.id
}

output "next_steps" {
  value = "Run: cloudscan aws --profile <your-sandbox-profile> --region ${var.region}"
}
