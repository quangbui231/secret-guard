
from secret_guard.detectors.entropy_detector import EntropyDetector


def test_calculate_entropy():
    detector = EntropyDetector()

    entropy = detector.calculate_entropy(
        "aaaaaaaaaaaaaaaa"
    )

    assert entropy == 0.0


def test_calculate_entropy_random_string():
    detector = EntropyDetector()

    entropy = detector.calculate_entropy(
        "a8Fj92KpQx7Lm4Rt"
    )

    assert entropy > 3.0



def test_detect_base64():
    detector = EntropyDetector()

    text = (
        'api_key = '
        '"aB3xQ9mL2vR7kT5zN8pW4cY6dF1gH0s="'
    )

    findings = detector.detect_base64(text)

    assert len(findings) > 0

    assert (
        findings[0]["type"]
        == "Base64 High Entropy String"
    )



def test_detect_hex():
    detector = EntropyDetector()

    text = (
        "secret = "
        "9f86d081884c7d659a2feaa0c55ad015"
    )

    findings = detector.detect_hex(text)

    assert len(findings) > 0

    assert (
        findings[0]["type"]
        == "Hex High Entropy String"
    )


def test_detect_generic():
    detector = EntropyDetector()

    text = (
        'token = "a8Fj92KpQx7Lm4Rt"'
    )

    findings = detector.detect_generic(text)

    assert len(findings) > 0


def test_ignore_short_string():
    detector = EntropyDetector()

    text = "abc123"

    findings = detector.detect(text)

    assert len(findings) == 0


def test_ignore_repeated_string():
    detector = EntropyDetector()

    text = (
        'token = "aaaaaaaaaaaaaaaa"'
    )

    findings = detector.detect(text)

    assert len(findings) == 0


def test_ignore_normal_text():
    detector = EntropyDetector()

    text = "hello world"

    findings = detector.detect(text)

    assert len(findings) == 0


def test_detect_returns_position():
    detector = EntropyDetector()

    text = (
        'token = "a8Fj92KpQx7Lm4Rt"'
    )

    findings = detector.detect_generic(text)

    assert len(findings) > 0

    finding = findings[0]

    assert finding["start"] >= 0
    assert finding["end"] > finding["start"]


def test_detect_non_string():
    detector = EntropyDetector()

    findings = detector.detect(None)

    assert findings == []
