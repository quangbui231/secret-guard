import pytest

from secret_guard.scanner import SecretScanner
from secret_guard.filters.secret_filter import SecretFilter
from secret_guard.main import SecretGuard


def scan(code, enabled=True, filename="example.py"):
    return SecretFilter().filter_findings(
        SecretScanner(enable_python_context=enabled).scan_text(code, filename))


@pytest.mark.parametrize("code", [
    'password = load_password()',
    'password = settings.password',
    'token = config["TOKEN"]',
    'password: str = load_password()',
    'settings.password = load_password()',
    'config["password"] = load_password()',
    'connect(password=load_password())',
    'config = {"password": load_password()}',
    'password = os.getenv("PASSWORD")',
    'password = os.environ.get("PASSWORD")',
])
def test_reference_is_not_a_literal_secret(code):
    assert scan(code) == []


@pytest.mark.parametrize("code", [
    'password = "DemoPass123!"',
    'password: str = "DemoPass123!"',
    'settings.password = "DemoPass123!"',
    'config["password"] = "DemoPass123!"',
    'config = {"password": "DemoPass123!"}',
    'config = {"nested": {"api_key": "DemoPass123!"}}',
    'connect(password="DemoPass123!")',
    'connect(client_secret="DemoPass123!")',
    'password = os.getenv("PASSWORD", "DemoPass123!")',
    'value = os.getenv("PASSWORD", "DemoPass123!")',
    'password = os.environ.get("PASSWORD", default="DemoPass123!")',
    'value = config.get("password", "DemoPass123!")',
    'value = os.getenv(key="PASSWORD", default="DemoPass123!")',
    'config = {"password": """DemoPass123!"""}',
])
def test_sensitive_literal_detected_with_context(code):
    found = [f for f in scan(code) if f.get("detector") == "Python AST"]
    assert any(f["secret"] == "DemoPass123!" for f in found)
    for f in found:
        assert code[f["start"]:f["end"]] == "DemoPass123!"
        assert f["context_reason"]


def test_default_not_removed_when_reference_on_same_line():
    code = 'password = load_password(); cfg = {"password": "DemoPass123!"}'
    assert any(f["secret"] == "DemoPass123!" for f in scan(code))
    assert not any("load_password" in f["secret"] for f in scan(code))


def test_unknown_call_preserves_entropy_in_argument():
    value = "aB3xQ9mL2vR7kT5zN8pW4cY6dF1gH0s"
    assert any(f["secret"] == value for f in scan(f'password = custom("{value}")'))


def test_literal_containing_code_words_is_not_a_reference():
    assert any(f["secret"] == "os.getenv.Password123!"
               for f in scan('password = "os.getenv.Password123!"'))


@pytest.mark.parametrize("code", [
    'cfg = {"password": "your_password_here"}',
    'connect(password="changeme")',
    'password = os.getenv("PASSWORD", "your_password_here")',
    'cfg = {"password": "abc"}',
    'cfg = {"title": "hello world"}',
])
def test_normal_or_placeholder_values_filtered(code):
    assert scan(code) == []


def test_unicode_positions_and_multiline():
    code = 'tên = "Việt"; cfg = {\n "password": "DemoPass123!"\n}'
    finding = next(f for f in scan(code) if f.get("detector") == "Python AST")
    assert finding["line"] == 2
    assert code[finding["start"]:finding["end"]] == finding["secret"]
    one_line = 'tên = "Việt"; cfg = {"password": "DemoPass123!"}'
    finding = next(f for f in scan(one_line) if f.get("detector") == "Python AST")
    assert one_line[finding["start"]:finding["end"]] == finding["secret"]


@pytest.mark.parametrize("code", [
    'cfg = {"password": "Demo\\x50ass123!"}',
    'cfg = {"password": "Demo" "Pass123!"}',
])
def test_escaped_and_adjacent_literals_have_valid_source_span(code):
    finding = next(f for f in scan(code) if f.get("detector") == "Python AST")
    assert finding["secret"] == "DemoPass123!"
    assert 0 <= finding["start"] < finding["end"] <= len(code)


@pytest.mark.parametrize("filename,code", [
    ("bad.py", 'password = "DemoPass123!"\n('),
    ("settings.yaml", 'password: "DemoPass123!"'),
    ("settings.json", '{"password": "DemoPass123!"}'),
    ("<memory>", 'password = load_password()'),
])
def test_fallback_matches_baseline(filename, code):
    assert scan(code, filename=filename) == scan(code, False, filename)


def test_merge_keeps_ast_evidence_and_masks_output():
    code = 'password = "DemoPass123!"'
    guard = SecretGuard()
    merged = guard._merge_findings(scan(code))
    assert len(merged) == 1
    assert "Python AST" in merged[0]["detected_by"]
    assert "Regex" in merged[0]["detected_by"]
    report = guard.reporter.generate_report(guard.policy_engine.evaluate(merged))
    assert "Context:" in report
    assert "DemoPass123!" not in report


def test_scanned_code_is_never_executed(tmp_path):
    marker = tmp_path / "should_not_exist"
    code = f'open({str(marker)!r}, "w").write("executed")\npassword = "DemoPass123!"'
    scan(code)
    assert not marker.exists()


def test_cli_decision_for_reference_and_literal(tmp_path, capsys):
    target = tmp_path / "sample.py"
    target.write_text('password = load_password()', encoding="utf-8")
    assert SecretGuard().run(target) == 0
    assert SecretGuard(enable_python_context=False).run(target) == 1
    target.write_text('cfg = {"password": "DemoPass123!"}', encoding="utf-8")
    assert SecretGuard().run(target) == 1
