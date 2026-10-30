
import pytest

from secret_guard.detectors.keyword_detector import KeywordDetector


@pytest.fixture
def detector():
    return KeywordDetector()


def test_detect_api_key(detector):
    text = 'API_KEY = "sk_test_abc123xyz"'

    findings = detector.detect(text)

    assert len(findings) == 1
    assert findings[0]["type"] == "Secret Keyword"
    assert findings[0]["secret"] == "sk_test_abc123xyz"
    assert findings[0]["keyword"] == "API_KEY"


def test_detect_database_password(detector):
    text = 'DB_PASSWORD = "MyDbPass123"'

    findings = detector.detect(text)

    assert len(findings) == 1
    assert findings[0]["secret"] == "MyDbPass123"


def test_detect_secret_with_colon(detector):
    text = 'client_secret: "client-secret-123"'

    findings = detector.detect(text)

    assert len(findings) == 1
    assert findings[0]["secret"] == "client-secret-123"


def test_detect_unquoted_value(detector):
    text = "api_key = abc123xyz789"

    findings = detector.detect(text)

    assert len(findings) == 1
    assert findings[0]["secret"] == "abc123xyz789"


def test_ignore_placeholder(detector):
    text = 'API_KEY = "your_api_key_here"'

    findings = detector.detect(text)

    assert findings == []


def test_ignore_environment_variable_reference(detector):
    text = 'DB_PASSWORD = "${DB_PASSWORD}"'

    findings = detector.detect(text)

    assert findings == []


def test_ignore_normal_variable(detector):
    text = 'APP_NAME = "my_application"'

    findings = detector.detect(text)

    assert findings == []


def test_ignore_short_value(detector):
    text = 'API_KEY = "abc"'

    findings = detector.detect(text)

    assert findings == []


def test_detect_returns_correct_position(detector):
    text = 'API_KEY = "sk_test_abc123xyz"'

    findings = detector.detect(text)

    assert len(findings) == 1

    finding = findings[0]
    assert text[finding["start"]:finding["end"]] == finding["secret"]


def test_non_string_input(detector):
    assert detector.detect(None) == []
    assert detector.detect(123) == []
    assert detector.detect("") == []
