"""
test_lambda_integration.py — Integration tests for lambda_checks.run().

These test the full run() orchestration with moto, covering the lines
that test_lambda.py (unit tests) leaves uncovered:
  - _list_functions() pagination
  - run() loop over functions
  - run() calling both checks per function
  - AccessDenied on list_functions is recorded, not raised
"""

import json
import boto3
import pytest
from moto import mock_aws

from cloudscan.aws_client import AWSClient
from cloudscan.checks.lambda_checks import run
from cloudscan.models import Severity


def _create_lambda_role(iam_client):
    """Create a minimal execution role for Lambda."""
    role = iam_client.create_role(
        RoleName="test-lambda-role",
        AssumeRolePolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }],
        }),
    )
    return role["Role"]["Arn"]


def _create_function(lmb_client, role_arn, name, env_vars=None):
    """Create a minimal Lambda function."""
    kwargs = {
        "FunctionName": name,
        "Runtime": "python3.12",
        "Role": role_arn,
        "Handler": "index.handler",
        "Code": {"ZipFile": b"PK\x05\x06" + b"\x00" * 18},
    }
    if env_vars:
        kwargs["Environment"] = {"Variables": env_vars}
    return lmb_client.create_function(**kwargs)


@mock_aws
def test_lambda_run_no_functions_returns_empty():
    boto3.client("sts", region_name="us-east-1").get_caller_identity()
    client = AWSClient(profile=None, region="us-east-1")
    findings = run(client)
    assert findings == []
    assert client.errors == []


@mock_aws
def test_lambda_run_detects_secret_env_var():
    boto3.client("sts", region_name="us-east-1").get_caller_identity()
    iam = boto3.client("iam", region_name="us-east-1")
    lmb = boto3.client("lambda", region_name="us-east-1")

    role_arn = _create_lambda_role(iam)
    _create_function(lmb, role_arn, "my-fn", env_vars={"DB_PASSWORD": "secret", "APP_ENV": "prod"})

    client = AWSClient(profile=None, region="us-east-1")
    findings = run(client)

    secret_findings = [f for f in findings if f.id == "LAMBDA_ENV_SECRET_EXPOSURE"]
    assert len(secret_findings) == 1
    assert secret_findings[0].resource == "my-fn"
    assert "DB_PASSWORD" in secret_findings[0].evidence
    # Value must NEVER appear in the finding
    assert "secret" not in secret_findings[0].evidence


@mock_aws
def test_lambda_run_clean_function_no_findings():
    boto3.client("sts", region_name="us-east-1").get_caller_identity()
    iam = boto3.client("iam", region_name="us-east-1")
    lmb = boto3.client("lambda", region_name="us-east-1")

    role_arn = _create_lambda_role(iam)
    _create_function(lmb, role_arn, "clean-fn", env_vars={"APP_ENV": "production", "LOG_LEVEL": "INFO"})

    client = AWSClient(profile=None, region="us-east-1")
    findings = run(client)

    assert findings == [], f"Expected no findings, got: {[f.id for f in findings]}"


@mock_aws
def test_lambda_run_multiple_functions():
    """run() must scan all functions, not just the first."""
    boto3.client("sts", region_name="us-east-1").get_caller_identity()
    iam = boto3.client("iam", region_name="us-east-1")
    lmb = boto3.client("lambda", region_name="us-east-1")

    role_arn = _create_lambda_role(iam)
    _create_function(lmb, role_arn, "fn-clean",  env_vars={"APP_ENV": "prod"})
    _create_function(lmb, role_arn, "fn-secret", env_vars={"API_KEY": "abc123"})
    _create_function(lmb, role_arn, "fn-token",  env_vars={"AUTH_TOKEN": "tok"})

    client = AWSClient(profile=None, region="us-east-1")
    findings = run(client)

    resources = {f.resource for f in findings if f.id == "LAMBDA_ENV_SECRET_EXPOSURE"}
    assert "fn-secret" in resources
    assert "fn-token" in resources
    assert "fn-clean" not in resources


@mock_aws
def test_lambda_run_records_error_on_list_denied():
    """If list_functions returns AccessDenied, run() records error and returns []."""
    from unittest.mock import MagicMock, patch
    from botocore.exceptions import ClientError

    boto3.client("sts", region_name="us-east-1").get_caller_identity()
    client = AWSClient(profile=None, region="us-east-1")

    mock_lmb = MagicMock()
    mock_paginator = MagicMock()
    mock_paginator.paginate.side_effect = ClientError(
        {"Error": {"Code": "AccessDenied", "Message": "denied"}}, "ListFunctions"
    )
    mock_lmb.get_paginator.return_value = mock_paginator

    with patch.object(client, "get_client", return_value=mock_lmb):
        findings = run(client)

    assert findings == []
    assert len(client.errors) == 1
    assert client.errors[0].error_type == "ACCESS_DENIED"
    assert client.errors[0].service == "Lambda"


@mock_aws
def test_lambda_run_false_positive_patterns_not_triggered():
    """Variables like OAUTH_REDIRECT_URL must NOT trigger LAMBDA_ENV_SECRET_EXPOSURE."""
    boto3.client("sts", region_name="us-east-1").get_caller_identity()
    iam = boto3.client("iam", region_name="us-east-1")
    lmb = boto3.client("lambda", region_name="us-east-1")

    role_arn = _create_lambda_role(iam)
    _create_function(lmb, role_arn, "oauth-fn", env_vars={
        "OAUTH_REDIRECT_URL": "https://example.com/callback",
        "AUTHOR_NAME": "Jane Doe",
        "TOKENIZER_VERSION": "v2",
        "APP_ENV": "production",
    })

    client = AWSClient(profile=None, region="us-east-1")
    findings = run(client)

    secret_findings = [f for f in findings if f.id == "LAMBDA_ENV_SECRET_EXPOSURE"]
    assert secret_findings == [], (
        f"False positive triggered for: "
        f"{[f.evidence for f in secret_findings]}"
    )
