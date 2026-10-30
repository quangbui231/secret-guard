
from secret_guard.detectors.regex_detector import RegexDetector


def test_detect_api_key():
    detector = RegexDetector()

    text = 'api_key = "abc123XYZ456"'

    results = detector.detect(text)

    assert len(results) == 1
    assert results[0]["type"] == "API Key"


def test_detect_password():
    detector = RegexDetector()

    text = 'password = "MyPass123"'

    results = detector.detect(text)

    assert len(results) == 1
    assert results[0]["type"] == "Password"


def test_detect_token():
    detector = RegexDetector()

    text = 'token = "tok_123456789"'

    results = detector.detect(text)

    assert len(results) == 1
    assert results[0]["type"] == "Token"


def test_no_secret():
    detector = RegexDetector()

    text = """
    name = "John"
    age = 20
    language = "Python"
    """

    results = detector.detect(text)

    assert len(results) == 0
