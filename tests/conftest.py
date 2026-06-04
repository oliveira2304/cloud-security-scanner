"""
conftest.py — Shared pytest fixtures.

What this file does:
  Provides reusable fixtures for mocking AWS services with moto.
  Every test that uses these fixtures gets a clean, isolated AWS environment
  — no real credentials needed, no state leaks between tests.

Why moto:
  moto intercepts boto3 calls and returns fake but realistic responses.
  Tests run in milliseconds and work offline. This is the standard approach
  for testing AWS Python code.

Pattern:
  1. Activate a moto mock (e.g. @mock_aws)
  2. Use boto3 to create resources in the fake environment
  3. Run the check function
  4. Assert on the findings
"""

import os
import boto3
import pytest


# Prevent any real AWS calls during tests
@pytest.fixture(autouse=True)
def aws_credentials():
    """Inject fake credentials so boto3 never tries to use real ones."""
    os.environ["AWS_ACCESS_KEY_ID"] = "testing"
    os.environ["AWS_SECRET_ACCESS_KEY"] = "testing"
    os.environ["AWS_SECURITY_TOKEN"] = "testing"
    os.environ["AWS_SESSION_TOKEN"] = "testing"
    os.environ["AWS_DEFAULT_REGION"] = "us-east-1"
    yield
