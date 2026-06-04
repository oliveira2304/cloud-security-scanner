"""
test_models.py — Unit tests for models and severity helpers.

These tests verify the severity comparison logic that powers --fail-on and --min-severity.
"""

import pytest

from cloudscan.models import Severity, severity_gte, SEVERITY_ORDER


def test_severity_order_is_critical_first():
    assert SEVERITY_ORDER[0] == Severity.CRITICAL
    assert SEVERITY_ORDER[-1] == Severity.LOW


def test_severity_gte_same_level():
    assert severity_gte(Severity.HIGH, Severity.HIGH) is True
    assert severity_gte(Severity.CRITICAL, Severity.CRITICAL) is True


def test_severity_gte_more_severe():
    assert severity_gte(Severity.CRITICAL, Severity.HIGH) is True
    assert severity_gte(Severity.HIGH, Severity.MEDIUM) is True
    assert severity_gte(Severity.MEDIUM, Severity.LOW) is True
    assert severity_gte(Severity.CRITICAL, Severity.LOW) is True


def test_severity_gte_less_severe():
    assert severity_gte(Severity.LOW, Severity.HIGH) is False
    assert severity_gte(Severity.MEDIUM, Severity.CRITICAL) is False
    assert severity_gte(Severity.HIGH, Severity.CRITICAL) is False


def test_fail_on_critical_only_triggers_on_critical():
    """Simulates: --fail-on CRITICAL"""
    findings_severities = [Severity.HIGH, Severity.MEDIUM, Severity.LOW]
    breaching = [s for s in findings_severities if severity_gte(s, Severity.CRITICAL)]
    assert breaching == []


def test_fail_on_high_triggers_on_high_and_critical():
    """Simulates: --fail-on HIGH"""
    findings_severities = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]
    breaching = [s for s in findings_severities if severity_gte(s, Severity.HIGH)]
    assert set(breaching) == {Severity.CRITICAL, Severity.HIGH}


def test_min_severity_high_filters_correctly():
    """Simulates: --min-severity HIGH"""
    findings_severities = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]
    displayed = [s for s in findings_severities if severity_gte(s, Severity.HIGH)]
    assert Severity.CRITICAL in displayed
    assert Severity.HIGH in displayed
    assert Severity.MEDIUM not in displayed
    assert Severity.LOW not in displayed
