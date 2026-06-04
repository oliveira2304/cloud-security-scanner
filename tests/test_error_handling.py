"""
test_error_handling.py — Verify that AccessDenied and API errors are never silently swallowed.

These tests ensure that when AWS returns an error, it surfaces as a ScanError
rather than disappearing — preventing false "clean" results.
"""

from unittest.mock import MagicMock, patch
from botocore.exceptions import ClientError

import pytest

from cloudscan.models import ScanError
from cloudscan.aws_client import AWSClient


def _make_access_denied() -> ClientError:
    return ClientError(
        {"Error": {"Code": "AccessDenied", "Message": "User is not authorized"}},
        "SomeOperation",
    )


def _make_api_error() -> ClientError:
    return ClientError(
        {"Error": {"Code": "InternalError", "Message": "Service unavailable"}},
        "SomeOperation",
    )


def test_record_error_access_denied_sets_correct_type():
    """record_error classifies AccessDenied correctly."""
    client = MagicMock(spec=AWSClient)
    client.errors = []

    # Call the real method, not the mock
    AWSClient.record_error(client, "S3", "_check_public_access", "my-bucket", _make_access_denied())

    assert len(client.errors) == 1
    assert client.errors[0].error_type == "ACCESS_DENIED"
    assert client.errors[0].service == "S3"
    assert client.errors[0].resource == "my-bucket"


def test_record_error_api_error_sets_correct_type():
    """record_error classifies non-AccessDenied errors as API_ERROR."""
    client = MagicMock(spec=AWSClient)
    client.errors = []

    AWSClient.record_error(client, "EC2", "describe_security_groups", "*", _make_api_error())

    assert len(client.errors) == 1
    assert client.errors[0].error_type == "API_ERROR"


def test_s3_run_calls_record_error_on_list_buckets_denied():
    """
    If list_buckets returns AccessDenied, run() must call client.record_error()
    and return empty findings — NOT crash or silently return "clean".

    We check record_error was called rather than inspecting client.errors directly
    because MagicMock(spec=AWSClient) replaces record_error with a mock that
    doesn't write to errors. The call itself is what matters: it proves the
    error was not swallowed.
    """
    from cloudscan.checks import s3

    mock_client = MagicMock(spec=AWSClient)
    mock_s3 = MagicMock()
    mock_s3.list_buckets.side_effect = _make_access_denied()
    mock_client.get_client.return_value = mock_s3

    findings = s3.run(mock_client)

    assert findings == []
    mock_client.record_error.assert_called_once()
    call_args = mock_client.record_error.call_args[0]
    assert call_args[0] == "S3"           # service
    assert call_args[1] == "list_buckets" # check name


def test_ec2_run_calls_record_error_on_describe_sg_denied():
    """If describe_security_groups returns AccessDenied, run() calls record_error."""
    from cloudscan.checks import ec2

    mock_client = MagicMock(spec=AWSClient)
    mock_ec2 = MagicMock()
    mock_paginator = MagicMock()
    mock_paginator.paginate.side_effect = _make_access_denied()
    mock_ec2.get_paginator.return_value = mock_paginator
    mock_client.get_client.return_value = mock_ec2

    findings = ec2.run(mock_client)

    assert findings == []
    mock_client.record_error.assert_called_once()
    call_args = mock_client.record_error.call_args[0]
    assert call_args[0] == "EC2"
