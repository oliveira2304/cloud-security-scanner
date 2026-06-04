/*
  terraform-lab/insecure-aws-lab/main.tf

  Purpose:
    Creates a deliberately insecure AWS environment to test cloudscan findings.
    Run this ONLY in a dedicated sandbox/test AWS account. Never in production.

  Resources created (all intentionally misconfigured):
    - S3: bucket with public access and no encryption
    - IAM: user without MFA + active access key + wildcard policy
    - EC2: Security Group with SSH/MySQL open to 0.0.0.0/0
    - RDS: MySQL instance that is public, unencrypted, no deletion protection
    - Lambda: function with AuthType=NONE URL + password env var

  After applying:
    cloudscan aws --profile sandbox --region us-east-1

  Expected findings: 14+ findings across all severities.

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
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
  }
}

provider "aws" {
  region = var.region
}

variable "region" {
  default     = "us-east-1"
  description = "AWS region for the lab resources."
}

resource "random_id" "suffix" {
  byte_length = 4
}

# ── S3: public bucket, no encryption, no versioning ─────────────────────────

resource "aws_s3_bucket" "vulnerable" {
  bucket        = "cloudscan-lab-${random_id.suffix.hex}"
  force_destroy = true
  tags          = { Purpose = "cloudscan-lab" }
}

resource "aws_s3_bucket_public_access_block" "vulnerable" {
  bucket                  = aws_s3_bucket.vulnerable.id
  block_public_acls       = false
  ignore_public_acls      = false
  block_public_policy     = false
  restrict_public_buckets = false
}

# ── IAM: user without MFA, wildcard policy ───────────────────────────────────

resource "aws_iam_user" "no_mfa" {
  name = "cloudscan-lab-no-mfa-user"
  tags = { Purpose = "cloudscan-lab" }
}

resource "aws_iam_access_key" "no_mfa" {
  user = aws_iam_user.no_mfa.name
}

resource "aws_iam_policy" "wildcard" {
  name        = "cloudscan-lab-wildcard-policy"
  description = "Intentionally insecure wildcard policy for cloudscan testing"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "*"
      Resource = "*"
    }]
  })
}

# ── EC2: Security Group with SSH + MySQL open ────────────────────────────────

resource "aws_security_group" "open_ports" {
  name        = "cloudscan-lab-open-ports"
  description = "Intentionally insecure SG — SSH and MySQL open to world"

  ingress {
    description = "SSH open to world (LAB ONLY)"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "MySQL open to world (LAB ONLY)"
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

  tags = { Purpose = "cloudscan-lab" }
}

# ── RDS: public MySQL instance, no encryption, no deletion protection ────────

resource "aws_db_instance" "vulnerable" {
  identifier             = "cloudscan-lab-db"
  engine                 = "mysql"
  engine_version         = "8.0"
  instance_class         = "db.t3.micro"
  allocated_storage      = 20
  db_name                = "labdb"
  username               = "admin"
  password               = "ChangeMe123!"   # pragma: allowlist secret
  skip_final_snapshot    = true

  # Intentionally misconfigured
  publicly_accessible    = true   # cloudscan: RDS_INSTANCE_PUBLIC
  storage_encrypted      = false  # cloudscan: RDS_ENCRYPTION_DISABLED
  deletion_protection    = false  # cloudscan: RDS_DELETION_PROTECTION_OFF
  multi_az               = false  # cloudscan: RDS_MULTI_AZ_DISABLED

  vpc_security_group_ids = [aws_security_group.open_ports.id]

  tags = { Purpose = "cloudscan-lab" }
}

# ── Lambda: public Function URL + password env var ───────────────────────────

resource "aws_iam_role" "lambda_exec" {
  name = "cloudscan-lab-lambda-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "lambda_basic" {
  role       = aws_iam_role.lambda_exec.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_lambda_function" "vulnerable" {
  function_name = "cloudscan-lab-vulnerable-fn"
  role          = aws_iam_role.lambda_exec.arn
  runtime       = "python3.12"
  handler       = "index.handler"
  filename      = data.archive_file.lambda_zip.output_path

  # Intentionally misconfigured: password stored in env var
  environment {
    variables = {
      DATABASE_PASSWORD = "super-secret-123"  # cloudscan: LAMBDA_ENV_SECRET_EXPOSURE
      APP_ENV           = "production"
    }
  }

  tags = { Purpose = "cloudscan-lab" }
}

# Intentionally misconfigured: AuthType=NONE
resource "aws_lambda_function_url" "vulnerable" {
  function_name      = aws_lambda_function.vulnerable.function_name
  authorization_type = "NONE"  # cloudscan: LAMBDA_PUBLIC_URL
}

data "archive_file" "lambda_zip" {
  type        = "zip"
  output_path = "/tmp/lambda_lab.zip"

  source {
    content  = "def handler(event, context): return {'statusCode': 200, 'body': 'lab'}"
    filename = "index.py"
  }
}

# ── Outputs ──────────────────────────────────────────────────────────────────

output "summary" {
  value = <<-EOT
    Lab created. Run cloudscan to find these misconfigurations:

    S3:
      Bucket          : ${aws_s3_bucket.vulnerable.bucket}
      Expected checks : S3_PUBLIC_ACCESS_BLOCK_DISABLED, S3_ENCRYPTION_DISABLED, S3_VERSIONING_DISABLED

    IAM:
      User            : ${aws_iam_user.no_mfa.name}
      Expected checks : IAM_USER_NO_MFA, IAM_POLICY_WILDCARD_ADMIN

    EC2:
      Security Group  : ${aws_security_group.open_ports.id}
      Expected checks : EC2_SG_SSH_OPEN, EC2_SG_MYSQL_OPEN

    RDS:
      DB Instance     : ${aws_db_instance.vulnerable.identifier}
      Expected checks : RDS_INSTANCE_PUBLIC, RDS_ENCRYPTION_DISABLED, RDS_DELETION_PROTECTION_OFF, RDS_MULTI_AZ_DISABLED

    Lambda:
      Function        : ${aws_lambda_function.vulnerable.function_name}
      Function URL    : ${aws_lambda_function_url.vulnerable.function_url}
      Expected checks : LAMBDA_PUBLIC_URL, LAMBDA_ENV_SECRET_EXPOSURE

    Scan command:
      cloudscan aws --profile <sandbox-profile> --region ${var.region}
  EOT
}
