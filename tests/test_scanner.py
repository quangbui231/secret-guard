
import importlib.util
import json
import shutil
import subprocess
from pathlib import Path

import pytest

from secret_guard.detectors.entropy_detector import EntropyDetector
from secret_guard.main import SecretGuard, main
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


# ----- Quét file và dự án thực tế -----


ROOT = Path(__file__).resolve().parent.parent


def found(text, filename="sample.txt"):
    return [finding["secret"] for finding in SecretScanner().scan_text(text, filename)]


# ----------------------------------------------------------------------
# Giảm báo nhầm trên mã thật
# ----------------------------------------------------------------------

@pytest.mark.parametrize(
    "text",
    [
        "handlers = template_context_processors",
        "raise RequestEntityTooLarge()",
        "see https://developer.mozilla.org/en-US/docs/Web/API/XMLHttpRequest",
        "name = my_reverse_custom_name_4",
        "      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
        '"integrity": "sha512-Abc123DefGhi456JklMno789PqrStu012VwxYz345"',
        "rev: 57b21406f092110c18776e39b0bda50d37c945c8",
    ],
)
def test_entropy_ignores_identifiers_urls_and_hashes(text):
    assert EntropyDetector().detect(text) == []


def test_entropy_still_flags_random_values():
    stripe_like = "sk_" + "live_9aF3kQ7mZ2xP8vL4tR6w"  # ghép chuỗi: tránh GitHub Push Protection
    findings = EntropyDetector().detect("value = " + stripe_like)

    assert findings and findings[0]["secret"] == stripe_like


def test_entropy_analyzes_only_value_of_name_value_pair():
    findings = EntropyDetector().detect("SOMETHING=aK3x9Qz2LmP8vR4tW6yB")

    assert [finding["secret"] for finding in findings][-1] == "aK3x9Qz2LmP8vR4tW6yB"


def test_keyword_and_regex_do_not_cross_lines():
    text = "if not app.secret_key:\n    return None\nelif not password:\n    error = 'x'\n"

    assert found(text, "app.txt") == []


def test_unquoted_expressions_in_other_languages_are_ignored():
    code = "const password = getPassword();\nconst token = req.headers['x-token'];\n"

    assert found(code, "app.js") == []
    assert set(found('const password = "Js_Pass!2026";', "app.js")) == {"Js_Pass!2026"}


def test_unquoted_values_in_env_files_are_kept():
    assert "Env_Pass!2026" in found("DB_PASSWORD=Env_Pass!2026\n", ".env")


def test_doc_expressions_are_ignored():
    text = (
        "    password = request.form['password']\n"
        "    password = PasswordField('New Password')\n"
        "    password = form.password.data\n"
    )

    assert found(text, "views.rst") == []


def test_python_annotations_are_not_secrets():
    text = "class A:\n    def f(self):\n        self._cv_token: contextvars.Token[AppContext] | None = None\n"

    assert found(text, "ctx.py") == []


def test_boolean_values_are_not_secrets(tmp_path):
    (tmp_path / "ci.yaml").write_text(
        "with:\n  persist-credentials: false\npermissions:\n  id-token: write\n",
        encoding="utf-8",
    )

    assert SecretGuard().scan_targets([tmp_path]).findings == []


# ----------------------------------------------------------------------
# Thu thập file và giao diện dòng lệnh
# ----------------------------------------------------------------------

def make_project(tmp_path):
    project = tmp_path / "project"
    (project / "src").mkdir(parents=True)
    (project / "node_modules" / "lib").mkdir(parents=True)
    (project / "tests").mkdir()
    (project / "src" / "settings.py").write_text('SECRET_KEY = "Src_Secret!2026"\n', encoding="utf-8")
    (project / "node_modules" / "lib" / "index.js").write_text('const password = "Dep_Pass!2026";\n', encoding="utf-8")
    (project / "tests" / "fixtures.py").write_text('password = "Test_Pass!2026"\n', encoding="utf-8")
    (project / "package-lock.json").write_text('{"integrity": "sha512-AAAA"}', encoding="utf-8")
    return project


def test_default_excludes_and_custom_excludes(tmp_path):
    project = make_project(tmp_path)

    default = SecretGuard().scan_targets([project])
    custom = SecretGuard(exclude_patterns=["tests"]).scan_targets([project])
    everything = SecretGuard(use_default_excludes=False).scan_targets([project])

    secrets = lambda outcome: sorted(finding["secret"] for finding in outcome.findings)

    assert secrets(default) == ["Src_Secret!2026", "Test_Pass!2026"]
    assert default.excluded == 2
    assert secrets(custom) == ["Src_Secret!2026"]
    assert "Dep_Pass!2026" in secrets(everything)


def test_multiple_targets(tmp_path):
    first = tmp_path / "a.env"
    second = tmp_path / "b.env"
    first.write_text("API_TOKEN=Tok_A_2026xyz\n", encoding="utf-8")
    second.write_text("API_TOKEN=Tok_B_2026xyz\n", encoding="utf-8")

    outcome = SecretGuard().scan_targets([first, second])

    assert sorted(finding["secret"] for finding in outcome.findings) == ["Tok_A_2026xyz", "Tok_B_2026xyz"]


@pytest.mark.skipif(shutil.which("git") is None, reason="cần git")
def test_respect_gitignore(tmp_path):
    project = tmp_path / "repo"
    project.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=project, check=True)
    (project / ".gitignore").write_text("local.env\n", encoding="utf-8")
    (project / "local.env").write_text("DB_PASSWORD=Ignored_Pass!1\n", encoding="utf-8")
    (project / "app.env").write_text("DB_PASSWORD=Tracked_Pass!1\n", encoding="utf-8")

    plain = SecretGuard().scan_targets([project])
    filtered = SecretGuard(respect_gitignore=True).scan_targets([project])

    assert {f["secret"] for f in plain.findings} == {"Ignored_Pass!1", "Tracked_Pass!1"}
    assert {f["secret"] for f in filtered.findings} == {"Tracked_Pass!1"}


def test_json_report_never_contains_raw_secret(tmp_path, capsys):
    target = tmp_path / ".env"
    target.write_text("DB_PASSWORD=Very_Secret_Value!2026\n", encoding="utf-8")
    report_file = tmp_path / "report.json"

    with pytest.raises(SystemExit) as exit_info:
        main([str(target), "--format", "json", "--output", str(report_file)])

    content = report_file.read_text(encoding="utf-8")
    report = json.loads(content)

    assert exit_info.value.code == 1
    assert "Very_Secret_Value!2026" not in content
    assert report["summary"]["block"] == 1
    assert report["findings"][0]["secret_masked"].startswith("Very")


def test_exit_codes(tmp_path):
    clean = tmp_path / "clean.py"
    clean.write_text("import os\npassword = os.getenv('DB_PASSWORD')\n", encoding="utf-8")

    with pytest.raises(SystemExit) as clean_exit:
        main([str(clean)])

    with pytest.raises(SystemExit) as missing_exit:
        main([str(tmp_path / "missing")])

    assert clean_exit.value.code == 0
    assert missing_exit.value.code == 2


# ----------------------------------------------------------------------
# Toàn bộ bộ file mẫu thực tế
# ----------------------------------------------------------------------

def test_real_world_samples_end_to_end(tmp_path):
    spec = importlib.util.spec_from_file_location(
        "generate_dataset", ROOT / "scripts" / "generate_dataset.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    samples = module.build_real_world_samples(tmp_path / "samples")

    outcome = SecretGuard().scan_targets([samples])
    by_file = {}

    for finding in outcome.findings:
        relative = Path(finding["filename"].split("!")[0]).relative_to(samples).as_posix()
        by_file.setdefault(relative, []).append(finding["action"])

    expected_files = {
        ".env", ".netrc", ".git-credentials", "Dockerfile",
        "deploy/sftp-config.json", "deploy/docker-compose.yml", "deploy/settings.xml",
        "web/wp-config.php", "web/app.js", "etc/.htpasswd",
        "legacy/utf16_config.ini", "legacy/cp1252_notes.txt",
        "docs/ban_giao.docx", "docs/tai_khoan.xlsx",
        "notebooks/phan_tich.ipynb",
        "backup/config_backup.zip", "backup/site.tar.gz", "backup/secrets.env.gz",
    }

    if importlib.util.find_spec("pypdf") is not None:
        expected_files.add("docs/huong_dan.pdf")

    assert set(by_file) == expected_files
    assert all(actions == ["BLOCK"] * len(actions) for actions in by_file.values())
    assert outcome.excluded == 1
    assert sorted(Path(item.name).name for item in outcome.skipped) == ["logo.png", "model.bin"]
