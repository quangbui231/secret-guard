
import pytest

from secret_guard.policy.policy_engine import PolicyEngine


@pytest.fixture
def engine():
    return PolicyEngine()


def test_private_key_is_critical(engine):
    finding = {
        "type": "Private Key",
        "secret": "PRIVATE_KEY_EXAMPLE",
    }

    result = engine.evaluate_finding(finding)

    assert result["severity"] == "CRITICAL"
    assert result["risk_score"] == 100
    assert result["action"] == "BLOCK"


def test_api_key_is_high(engine):
    finding = {
        "type": "API Key",
        "secret": "example_api_key_value",
    }

    result = engine.evaluate_finding(finding)

    assert result["severity"] == "HIGH"
    assert result["risk_score"] == 80
    assert result["action"] == "BLOCK"


def test_high_entropy_is_medium(engine):
    finding = {
        "type": "High Entropy",
        "secret": "aB3xQ9mL2vR7kT5z",
    }

    result = engine.evaluate_finding(finding)

    assert result["severity"] == "MEDIUM"
    assert result["risk_score"] == 50
    assert result["action"] == "REVIEW"


def test_unknown_type_uses_default_policy(engine):
    finding = {
        "type": "Unknown Detector Type",
        "secret": "example_value",
    }

    result = engine.evaluate_finding(finding)

    assert result["severity"] == "LOW"
    assert result["risk_score"] == 20
    assert result["action"] == "REVIEW"


def test_evaluate_multiple_findings(engine):
    findings = [
        {"type": "Private Key", "secret": "private_key_example"},
        {"type": "API Key", "secret": "api_key_example"},
        {"type": "High Entropy", "secret": "random_value_example"},
    ]

    results = engine.evaluate(findings)

    assert len(results) == 3
    assert results[0]["severity"] == "CRITICAL"
    assert results[1]["severity"] == "HIGH"
    assert results[2]["severity"] == "MEDIUM"


def test_summarize_findings(engine):
    findings = [
        {"type": "Private Key", "secret": "private_key_example"},
        {"type": "API Key", "secret": "api_key_example"},
        {"type": "High Entropy", "secret": "random_value_example"},
        {"type": "Unknown Type", "secret": "unknown_value"},
    ]

    evaluated = engine.evaluate(findings)
    summary = engine.summarize(evaluated)

    assert summary["total"] == 4
    assert summary["by_severity"]["CRITICAL"] == 1
    assert summary["by_severity"]["HIGH"] == 1
    assert summary["by_severity"]["MEDIUM"] == 1
    assert summary["by_severity"]["LOW"] == 1
    assert summary["by_action"]["BLOCK"] == 2
    assert summary["by_action"]["REVIEW"] == 2


def test_custom_policy_overrides_default():
    engine = PolicyEngine(
        custom_policies={
            "api key": {
                "severity": "CRITICAL",
                "score": 100,
                "action": "BLOCK",
                "reason": "Custom security policy.",
            }
        }
    )

    result = engine.evaluate_finding({
        "type": "API Key",
        "secret": "example_api_key_value",
    })

    assert result["severity"] == "CRITICAL"
    assert result["risk_score"] == 100
    assert result["policy_reason"] == "Custom security policy."


def test_invalid_inputs_raise_errors(engine):
    with pytest.raises(TypeError):
        engine.evaluate_finding("not a dictionary")

    with pytest.raises(TypeError):
        engine.evaluate("not a list")

    with pytest.raises(TypeError):
        engine.summarize("not a list")
