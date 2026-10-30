
import pytest
import yaml

from secret_guard.filters.allowlist import Allowlist


def test_allow_exact_secret():
    allowlist = Allowlist(
        allowed_secrets=["EXAMPLE_API_KEY_123456"]
    )

    finding = {
        "type": "API Key",
        "secret": "EXAMPLE_API_KEY_123456", 
    }

    assert allowlist.is_allowlisted(finding) is True


def test_do_not_allow_partial_secret():
    allowlist = Allowlist(
        allowed_secrets=["EXAMPLE_API_KEY_123456"]
    )

    finding = {
        "type": "API Key",
        "secret": "EXAMPLE_API_KEY_123456_EXTRA",
    }

    assert allowlist.is_allowlisted(finding) is False


def test_secret_not_in_allowlist():
    allowlist = Allowlist(
        allowed_secrets=["EXAMPLE_API_KEY_123456"]
    )

    finding = {
        "type": "API Key",
        "secret": "DIFFERENT_SECRET_987654",
    }

    assert allowlist.is_allowlisted(finding) is False


def test_allow_exact_file_and_line():
    allowlist = Allowlist(
        allowed_locations=[
            {
                "filename": "tests/example.py",
                "line": 10,
            }
        ]
    )

    finding = {
        "type": "API Key",
        "secret": "EXAMPLE_API_KEY_123456",
        "filename": "tests/example.py",
        "line": 10,
    }

    assert allowlist.is_allowlisted(finding) is True


def test_do_not_allow_different_line():
    allowlist = Allowlist(
        allowed_locations=[
            {
                "filename": "tests/example.py",
                "line": 10,
            }
        ]
    )

    finding = {
        "type": "API Key",
        "secret": "EXAMPLE_API_KEY_123456",
        "filename": "tests/example.py",
        "line": 11,
    }

    assert allowlist.is_allowlisted(finding) is False


def test_do_not_allow_different_file():
    allowlist = Allowlist(
        allowed_locations=[
            {
                "filename": "tests/example.py",
                "line": 10,
            }
        ]
    )

    finding = {
        "type": "API Key",
        "secret": "EXAMPLE_API_KEY_123456",
        "filename": "tests/another.py",
        "line": 10,
    }

    assert allowlist.is_allowlisted(finding) is False


def test_load_yaml_config(tmp_path):
    config_file = tmp_path / "allowlist.yaml"

    config_file.write_text(
        """
allowed_secrets:
  - EXAMPLE_API_KEY_123456

allowed_locations:
  - filename: tests/example.py
    line: 10
""",
        encoding="utf-8",
    )

    allowlist = Allowlist(config_path=config_file)

    assert allowlist.is_allowlisted({
        "secret": "EXAMPLE_API_KEY_123456"
    }) is True

    assert allowlist.is_allowlisted({
        "secret": "ANOTHER_SECRET_987654",
        "filename": "tests/example.py",
        "line": 10,
    }) is True


def test_load_empty_yaml_config(tmp_path):
    config_file = tmp_path / "allowlist.yaml"
    config_file.write_text("", encoding="utf-8")

    allowlist = Allowlist(config_path=config_file)

    assert allowlist.allowed_secrets == set()
    assert allowlist.allowed_locations == []


def test_missing_config_file():
    with pytest.raises(FileNotFoundError):
        Allowlist(config_path="nonexistent_allowlist.yaml")


def test_invalid_yaml_config(tmp_path):
    config_file = tmp_path / "allowlist.yaml"

    config_file.write_text(
        "allowed_secrets: [invalid",
        encoding="utf-8",
    )

    with pytest.raises(ValueError):
        Allowlist(config_path=config_file)


def test_filter_findings():
    allowlist = Allowlist(
        allowed_secrets=["EXAMPLE_API_KEY_123456"]
    )

    findings = [
        {
            "type": "API Key",
            "secret": "EXAMPLE_API_KEY_123456",
        },
        {
            "type": "Password",
            "secret": "REAL_PASSWORD_98765",
        },
    ]

    results = allowlist.filter_findings(findings)

    assert len(results) == 1
    assert results[0]["secret"] == "REAL_PASSWORD_98765"


def test_filter_does_not_modify_original():
    allowlist = Allowlist(
        allowed_secrets=["EXAMPLE_API_KEY_123456"]
    )

    findings = [
        {
            "type": "API Key",
            "secret": "EXAMPLE_API_KEY_123456",
        },
        {
            "type": "Password",
            "secret": "REAL_PASSWORD_98765",
        },
    ]

    original_length = len(findings)

    allowlist.filter_findings(findings)

    assert len(findings) == original_length


def test_invalid_finding_input():
    allowlist = Allowlist()

    with pytest.raises(TypeError):
        allowlist.is_allowlisted("invalid")

    with pytest.raises(TypeError):
        allowlist.filter_findings("invalid")


def test_invalid_location():
    with pytest.raises(TypeError):
        Allowlist(
            allowed_locations=[
                {"filename": "example.py", "line": "10"}
            ]
        )


def test_invalid_yaml_structure(tmp_path):
    config_file = tmp_path / "allowlist.yaml"

    config_file.write_text(
        yaml.safe_dump(["invalid", "structure"]),
        encoding="utf-8",
    )

    with pytest.raises(ValueError):
        Allowlist(config_path=config_file)
