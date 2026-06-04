"""
test_lambda.py — Unit and integration tests for Lambda checks.
"""

import boto3
import pytest
from unittest.mock import MagicMock, patch
from botocore.exceptions import ClientError

from cloudscan.checks.lambda_checks import _check_function_url, _check_env_secrets
from cloudscan.models import Severity


def _make_function(**overrides) -> dict:
    """Build a minimal Lambda function dict."""
    base = {
        "FunctionName": "my-function",
        "FunctionArn": "arn:aws:lambda:us-east-1:123456789012:function:my-function",
        "Environment": {"Variables": {}},
    }
    base.update(overrides)
    return base


def _make_url_config(auth_type: str) -> dict:
    return {
        "FunctionUrl": "https://abc123.lambda-url.us-east-1.on.aws/",
        "FunctionArn": "arn:aws:lambda:us-east-1:123456789012:function:my-function",
        "AuthType": auth_type,
    }


def _make_not_found_error() -> ClientError:
    return ClientError(
        {"Error": {"Code": "ResourceNotFoundException", "Message": "Not found"}},
        "GetFunctionUrlConfig",
    )


# ── Function URL: AuthType=NONE ───────────────────────────────────────────────

def test_public_url_reports_critical():
    lmb = MagicMock()
    lmb.get_function_url_config.return_value = _make_url_config("NONE")

    findings = _check_function_url(lmb, "my-function", "arn:...")

    assert len(findings) == 1
    assert findings[0].id == "LAMBDA_PUBLIC_URL"
    assert findings[0].severity == Severity.CRITICAL
    assert "AuthType: NONE" in findings[0].evidence


def test_iam_auth_url_no_finding():
    lmb = MagicMock()
    lmb.get_function_url_config.return_value = _make_url_config("AWS_IAM")

    findings = _check_function_url(lmb, "my-function", "arn:...")

    assert findings == []


def test_no_url_configured_no_finding():
    """ResourceNotFoundException means no URL exists — safe."""
    lmb = MagicMock()
    lmb.get_function_url_config.side_effect = _make_not_found_error()

    findings = _check_function_url(lmb, "my-function", "arn:...")

    assert findings == []


def test_other_client_error_bubbles_up():
    """Non-NotFound ClientErrors should propagate for record_error() to handle."""
    lmb = MagicMock()
    lmb.get_function_url_config.side_effect = ClientError(
        {"Error": {"Code": "AccessDenied", "Message": "denied"}},
        "GetFunctionUrlConfig",
    )

    with pytest.raises(ClientError):
        _check_function_url(lmb, "my-function", "arn:...")


# ── Environment variable secrets ──────────────────────────────────────────────

def test_password_env_var_reports_high():
    fn = _make_function(Environment={"Variables": {
        "DATABASE_PASSWORD": "secret123",
        "APP_ENV": "production",
    }})
    findings = _check_env_secrets(fn, "my-function")

    assert len(findings) == 1
    assert findings[0].id == "LAMBDA_ENV_SECRET_EXPOSURE"
    assert findings[0].severity == Severity.HIGH
    assert "DATABASE_PASSWORD" in findings[0].evidence
    assert "secret123" not in findings[0].evidence  # value must NOT appear


def test_multiple_secret_vars_single_finding():
    fn = _make_function(Environment={"Variables": {
        "DB_PASSWORD": "pass",
        "API_KEY": "key123",
        "APP_NAME": "myapp",
    }})
    findings = _check_env_secrets(fn, "my-function")

    assert len(findings) == 1
    assert "DB_PASSWORD" in findings[0].evidence
    assert "API_KEY" in findings[0].evidence
    # Values never appear
    assert "pass" not in findings[0].evidence
    assert "key123" not in findings[0].evidence


def test_clean_env_vars_no_finding():
    fn = _make_function(Environment={"Variables": {
        "APP_ENV": "production",
        "LOG_LEVEL": "INFO",
        "REGION": "us-east-1",
    }})
    findings = _check_env_secrets(fn, "my-function")
    assert findings == []


def test_no_env_vars_no_finding():
    fn = _make_function(Environment={"Variables": {}})
    findings = _check_env_secrets(fn, "my-function")
    assert findings == []


def test_missing_environment_key_no_finding():
    fn = _make_function()
    del fn["Environment"]
    findings = _check_env_secrets(fn, "my-function")
    assert findings == []


# ── Secret name pattern coverage ─────────────────────────────────────────────

@pytest.mark.parametrize("var_name", [
    "PASSWORD", "DB_PASSWORD", "DATABASE_PASSWORD",
    "SECRET", "API_SECRET", "APP_SECRET_KEY",
    "API_KEY", "STRIPE_API_KEY",
    "ACCESS_KEY", "AWS_SECRET_ACCESS_KEY",
    "PRIVATE_KEY", "RSA_PRIVATE_KEY",
    "TOKEN", "AUTH_TOKEN", "GITHUB_TOKEN",
    "AUTH", "BASIC_AUTH",
    "CREDENTIAL", "DB_CREDENTIALS",
    "DB_PASS", "DATABASE_URL",
    "CONNECTION_STRING",
])
def test_secret_pattern_detected(var_name):
    fn = _make_function(Environment={"Variables": {var_name: "value"}})
    findings = _check_env_secrets(fn, "my-function")
    assert findings, f"Pattern not detected for variable name: {var_name}"


# ── Compliance ────────────────────────────────────────────────────────────────

def test_lambda_findings_have_compliance():
    lmb = MagicMock()
    lmb.get_function_url_config.return_value = _make_url_config("NONE")

    findings = _check_function_url(lmb, "fn", "arn:...")
    assert findings[0].compliance
    assert "NIST_800_53" in findings[0].compliance

    fn = _make_function(Environment={"Variables": {"DB_PASSWORD": "x"}})
    findings2 = _check_env_secrets(fn, "fn")
    assert findings2[0].compliance
    assert "NIST_800_53" in findings2[0].compliance
