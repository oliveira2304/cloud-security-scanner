"""
checks/lambda_checks.py — AWS Lambda security checks.

Checks:
  1. LAMBDA_PUBLIC_URL          — Function URL with AuthType=NONE (CRITICAL)
  2. LAMBDA_ENV_SECRET_EXPOSURE — Environment variable names matching secret patterns (HIGH)

Why Function URLs matter:
  Lambda Function URLs (introduced 2022) let you invoke Lambda via HTTPS without
  API Gateway. AuthType=NONE means anyone on the internet can call the function
  with no authentication — a common misconfiguration in quick prototypes that
  make it to production.

Why environment variable scanning matters:
  Environment variables are often used to pass secrets to Lambda functions.
  They are visible in the AWS console, in CloudTrail logs, and to anyone with
  lambda:GetFunctionConfiguration. We flag variable *names* that match common
  secret patterns — we never read the values.

IAM permissions required:
  lambda:ListFunctions
  lambda:GetFunctionUrlConfig
  lambda:GetFunctionConfiguration   (for env var check)
"""

import logging
import re
from typing import List

from botocore.exceptions import ClientError

from cloudscan.aws_client import AWSClient
from cloudscan.compliance import get_compliance
from cloudscan.models import Finding, Severity

logger = logging.getLogger(__name__)

# Patterns that suggest a variable name holds a secret.
# We match names only — never read or log values.
#
# Design notes:
#   - `token` and `auth` use a negative-lookbehind/ahead to avoid false
#     positives like TOKENIZER_VERSION, OAUTH_REDIRECT_URL, AUTHOR_NAME.
#     They only match when not immediately surrounded by other letters.
#   - All other terms are specific enough that word-boundary issues don't apply.
_SECRET_NAME_PATTERNS = re.compile(
    r"(password|passwd|secret|api[_-]?key|access[_-]?key|private[_-]?key"
    r"|(?<![a-zA-Z])(token|auth)(?![a-zA-Z])"
    r"|credential|db[_-]?pass|database[_-]?url|connection[_-]?string"
    r"|stripe|twilio|sendgrid|github[_-]?token|aws[_-]?secret)",
    re.IGNORECASE,
)


def run(client: AWSClient) -> List[Finding]:
    lmb = client.get_client("lambda")
    findings: List[Finding] = []

    functions = _list_functions(lmb, client)
    for fn in functions:
        fn_name = fn["FunctionName"]
        fn_arn = fn["FunctionArn"]
        logger.debug("Scanning Lambda function: %s", fn_name)

        try:
            findings.extend(_check_function_url(lmb, fn_name, fn_arn))
        except ClientError as e:
            client.record_error("Lambda", "_check_function_url", fn_name, e)

        try:
            findings.extend(_check_env_secrets(fn, fn_name))
        except ClientError as e:
            client.record_error("Lambda", "_check_env_secrets", fn_name, e)

    return findings


def _list_functions(lmb_client, client: AWSClient) -> list:
    functions = []
    try:
        paginator = lmb_client.get_paginator("list_functions")
        for page in paginator.paginate():
            functions.extend(page.get("Functions", []))
    except ClientError as e:
        client.record_error("Lambda", "list_functions", "*", e)
    return functions


def _check_function_url(lmb_client, fn_name: str, fn_arn: str) -> List[Finding]:
    """
    Check if the function has a Function URL configured with AuthType=NONE.

    GetFunctionUrlConfig raises ResourceNotFoundException if no URL is configured —
    that is the expected "safe" case. Any other ClientError bubbles up to run().
    """
    try:
        config = lmb_client.get_function_url_config(FunctionName=fn_name)
    except ClientError as e:
        if e.response["Error"]["Code"] == "ResourceNotFoundException":
            return []  # No URL configured — safe
        raise

    auth_type = config.get("AuthType", "NONE")
    url = config.get("FunctionUrl", fn_arn)

    if auth_type == "NONE":
        return [Finding(
            id="LAMBDA_PUBLIC_URL",
            service="Lambda",
            resource=fn_name,
            severity=Severity.CRITICAL,
            title="Lambda function URL is publicly accessible without authentication",
            description=(
                f"Function '{fn_name}' has a Function URL configured with AuthType=NONE. "
                "Any request to this URL invokes the function without any authentication — "
                "no IAM, no API key, nothing. This is equivalent to a public API endpoint."
            ),
            recommendation=(
                "Set AuthType=AWS_IAM to require SigV4 signed requests. "
                "If public access is intentional, add application-level authentication "
                "(JWT verification, custom authorizer) inside the function. "
                "Consider using API Gateway with a Cognito or Lambda authorizer instead."
            ),
            evidence=f"FunctionUrl: {url}, AuthType: {auth_type}",
            compliance=get_compliance("LAMBDA_PUBLIC_URL"),
        )]

    return []


def _check_env_secrets(fn: dict, fn_name: str) -> List[Finding]:
    """
    Detect environment variable names that suggest a secret is stored in plain text.

    We scan variable NAMES only — values are never read, logged, or included
    in the finding. The finding flags the pattern so engineers can investigate.
    """
    env_vars = fn.get("Environment", {}).get("Variables", {})
    if not env_vars:
        return []

    suspicious = [
        name for name in env_vars
        if _SECRET_NAME_PATTERNS.search(name)
    ]

    if not suspicious:
        return []

    return [Finding(
        id="LAMBDA_ENV_SECRET_EXPOSURE",
        service="Lambda",
        resource=fn_name,
        severity=Severity.HIGH,
        title="Lambda function may store secrets in environment variables",
        description=(
            f"Function '{fn_name}' has environment variable(s) with names that suggest "
            "secrets are stored in plain text. Environment variables are visible in the "
            "AWS console, in GetFunctionConfiguration responses, and in CloudTrail logs."
        ),
        recommendation=(
            "Move secrets to AWS Secrets Manager or AWS Systems Manager Parameter Store (SecureString). "
            "Retrieve them at runtime using the AWS SDK. "
            "This removes secrets from the function configuration and adds rotation capability."
        ),
        evidence=f"Suspicious variable names: {', '.join(suspicious)} (values not read)",
        compliance=get_compliance("LAMBDA_ENV_SECRET_EXPOSURE"),
    )]
