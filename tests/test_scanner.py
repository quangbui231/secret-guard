
import pytest

from secret_guard.scanner import SecretScanner


@pytest.fixture
def scanner():
    return SecretScanner()


def test_scan_text_detects_secret(scanner):
    text = 'API_KEY = "sk_test_abc123xyz"'

    findings = scanner.scan_text(text)

    assert len(findings) >= 1
    assert any(
        finding["secret"] == "sk_test_abc123xyz"
        for finding in findings
    )


def test_scan_text_records_filename(scanner):
    text = 'API_KEY = "sk_test_abc123xyz"'

    findings = scanner.scan_text(
        text,
        filename="sample.py",
    )

    assert len(findings) >= 1
    assert all(
        finding["filename"] == "sample.py"
        for finding in findings
    )


def test_scan_text_records_line_number(scanner):
    text = (
        "APP_NAME = 'demo'\n"
        'API_KEY = "sk_test_abc123xyz"'
    )

    findings = scanner.scan_text(text)

    api_findings = [
        finding for finding in findings
        if finding["secret"] == "sk_test_abc123xyz"
    ]

    assert len(api_findings) >= 1
    assert all(finding["line"] == 2 for finding in api_findings)


def test_scan_normal_text(scanner):
    text = "APP_NAME = 'demo'\nVERSION = '1.0'"

    findings = scanner.scan_text(text)

    assert findings == []


def test_scan_text_rejects_non_string(scanner):
    with pytest.raises(TypeError):
        scanner.scan_text(None)


def test_scan_file_not_found(scanner, tmp_path):
    missing_file = tmp_path / "missing.py"

    with pytest.raises(FileNotFoundError):
        scanner.scan_file(missing_file)


def test_scan_file(scanner, tmp_path):
    sample_file = tmp_path / "sample.py"
    sample_file.write_text(
        'API_KEY = "sk_test_abc123xyz"',
        encoding="utf-8",
    )

    findings = scanner.scan_file(sample_file)

    assert len(findings) >= 1
    assert any(
        finding["secret"] == "sk_test_abc123xyz"
        for finding in findings
    )
