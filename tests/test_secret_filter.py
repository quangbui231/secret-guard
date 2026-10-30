
import pytest

from secret_guard.filters.secret_filter import SecretFilter


@pytest.fixture
def secret_filter():
    return SecretFilter()


def test_keeps_valid_secret(secret_filter):
    findings = [
        {
            "type": "API Key",
            "secret": "sk_live_A8x9Q2m7P4v6",
            "filename": "config.py",
            "start": 10,
            "end": 30,
        }
    ]

    results = secret_filter.filter_findings(findings)

    assert len(results) == 1
    assert results[0]["secret"] == "sk_live_A8x9Q2m7P4v6"


def test_removes_placeholder(secret_filter):
    findings = [
        {"type": "Password", "secret": "your_password_here"},
        {"type": "API Key", "secret": "changeme"},
    ]

    results = secret_filter.filter_findings(findings)

    assert results == []


def test_removes_environment_variable_reference(secret_filter):
    findings = [
        {"type": "API Key", "secret": "$API_KEY"},
        {"type": "API Key", "secret": "${API_KEY}"},
    ]

    results = secret_filter.filter_findings(findings)

    assert results == []


def test_removes_template_variable_reference(secret_filter):
    findings = [
        {"type": "Secret Keyword", "secret": "{{ API_KEY }}"},
    ]

    results = secret_filter.filter_findings(findings)

    assert results == []


def test_removes_short_secret():
    filter_instance = SecretFilter(min_length=8)

    findings = [
        {"type": "API Key", "secret": "abc123"},
        {"type": "API Key", "secret": "abc12345"},
    ]

    results = filter_instance.filter_findings(findings)

    assert len(results) == 1
    assert results[0]["secret"] == "abc12345"


def test_removes_secret_matching_custom_regex():
    filter_instance = SecretFilter(
        excluded_patterns=[r"^TEST_ONLY_"]
    )

    findings = [
        {"type": "API Key", "secret": "TEST_ONLY_123456"},
        {"type": "API Key", "secret": "prod_key_987654"},
    ]

    results = filter_instance.filter_findings(findings)

    assert len(results) == 1
    assert results[0]["secret"] == "prod_key_987654"


def test_removes_duplicate_findings(secret_filter):
    finding = {
        "type": "API Key",
        "secret": "prod_key_123456",
        "filename": "config.py",
        "start": 10,
        "end": 24,
    }

    results = secret_filter.filter_findings([
        finding,
        finding.copy(),
    ])

    assert len(results) == 1


def test_keeps_same_secret_at_different_positions(secret_filter):
    first = {
        "type": "API Key",
        "secret": "prod_key_123456",
        "filename": "config.py",
        "start": 10,
        "end": 24,
    }

    second = {
        "type": "API Key",
        "secret": "prod_key_123456",
        "filename": "config.py",
        "start": 50,
        "end": 64,
    }

    results = secret_filter.filter_findings([first, second])

    assert len(results) == 2


def test_does_not_modify_original_findings(secret_filter):
    finding = {
        "type": "API Key",
        "secret": "prod_key_123456",
        "filename": "config.py",
    }

    original = finding.copy()

    secret_filter.filter_findings([finding])

    assert finding == original


def test_invalid_inputs_raise_errors(secret_filter):
    with pytest.raises(TypeError):
        secret_filter.filter_findings("not a list")

    with pytest.raises(TypeError):
        secret_filter.filter_findings([
            "not a finding dictionary"
        ])

    with pytest.raises(TypeError):
        SecretFilter(min_length="4")

    with pytest.raises(ValueError):
        SecretFilter(min_length=0)

    with pytest.raises(ValueError):
        SecretFilter(excluded_patterns=["["])
