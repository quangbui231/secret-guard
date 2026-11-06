
import pytest

from secret_guard.detectors.keyword_detector import FormatDetector, KeywordDetector, is_sensitive_name


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


# ----- FormatDetector: định dạng file cấu hình thực tế -----


@pytest.fixture
def format_detector():
    return FormatDetector()


def format_secrets(format_detector, text, **kwargs):
    return [finding["secret"] for finding in format_detector.detect(text, **kwargs)]


@pytest.mark.parametrize(
    "name, structured, expected",
    [
        ("password", False, True),
        ("sshUserPassword", False, True),
        ("DB_PASS", False, True),
        ("IRC_PASS", False, True),
        ("sshPassphrase", False, True),
        ("clientsecret", False, True),
        ("api_key", False, True),
        ("pass", False, False),
        ("pass", True, True),
        ("auth", True, True),
        ("local_auth", False, False),
        ("passwordField", True, False),
        ("secretary", False, False),
        ("FLASK_MYAPI__credentials__username", False, False),
        ("tokenizer", False, False),
    ],
)
def test_is_sensitive_name(name, structured, expected):
    assert is_sensitive_name(name, structured=structured) is expected


def test_json_and_dict_keys(format_detector):
    text = '{\n  "host": "example.com",\n  "userPassword": "mongopass1",\n  "passwordField": "password"\n}'

    assert format_secrets(format_detector, text) == ["mongopass1"]


def test_quoted_keys_can_be_disabled(format_detector):
    assert format_secrets(format_detector, '{"password": "hunter22"}', quoted_keys=False) == []


def test_php_array_arrow(format_detector):
    assert format_secrets(format_detector, "$config = ['db_password' => 'Arr_Pass!1'];") == ["Arr_Pass!1"]


def test_php_define(format_detector):
    text = (
        "define( 'DB_NAME', 'main' );\n"
        "define( 'DB_PASSWORD', 'Wp_Pass!1' );\n"
        "define('AUTH_KEY', 'k8#Lm2$Qp9@Zx4&Vb7!Nc1');\n"
        "define('AUTH_SALT', 'j@cGIZJfObpPU);AZgYH5');\n"
    )

    assert format_secrets(format_detector, text) == ["Wp_Pass!1", "k8#Lm2$Qp9@Zx4&Vb7!Nc1", "j@cGIZJfObpPU);AZgYH5"]


def test_xml_elements(format_detector):
    text = '<Server><User>root</User><Pass encoding="base64">NjllNWU5ZWMw</Pass></Server>'

    assert format_secrets(format_detector, text) == ["NjllNWU5ZWMw"]


def test_url_credentials_any_scheme(format_detector):
    assert format_secrets(format_detector, "https://user@example.com:password!#@498@github.com") == ["password!#@498"]
    assert format_secrets(format_detector, "amqp://guest:Rabbit_Pass!1@mq.local:5672/") == ["Rabbit_Pass!1"]
    assert format_secrets(format_detector, "redis://:Redis_Pass!1@cache:6379") == ["Redis_Pass!1"]


def test_url_credentials_templates_are_ignored(format_detector):
    assert format_secrets(format_detector, "postgres://user:${DB_PASSWORD}@db/app") == []
    assert format_secrets(format_detector, "https://{user}:{password}@host") == []


def test_netrc(format_detector):
    text = "machine imap.gmail.com login me@example.com password pass123x"

    assert format_secrets(format_detector, text) == ["pass123x"]


def test_keyword_then_quoted_value(format_detector):
    text = 'username "me@example.com"\npassword "Esmtp_Pass!1"\n'

    assert format_secrets(format_detector, text) == ["Esmtp_Pass!1"]


def test_pgpass_requires_exactly_five_fields(format_detector):
    assert format_secrets(format_detector, "localhost:5432:database:root:Pg_Pass1") == ["Pg_Pass1"]
    assert format_secrets(format_detector, "daemon:*:17431:0:99999:7:::") == []


def test_crypt_password_hashes(format_detector):
    text = (
        "admin:$apr1$tp8glkbm$fjg65tI1eipoBh62aEjIy0\n"
        "ubuntu:$6$LnUhhUi45srUKt9i$4Hp6VRTOB2mxvsYH8mwsCfBryg6hCbm4JJjV26KplN8:17431:0:99999:7:::\n"
    )

    found = format_detector.detect(text)

    assert [finding["type"] for finding in found] == ["Password Hash", "Password Hash"]
    assert found[0]["secret"].startswith("$apr1$")


def test_findings_carry_detector_name_and_reason(format_detector):
    finding = format_detector.detect('{"password": "hunter22"}')[0]

    assert finding["detector"] == "Format"
    assert "password" in finding["context_reason"]
