"""
Phát hiện secret dựa trên tên biến và từ khóa nhạy cảm.

- KeywordDetector: phép gán dạng `ten = gia_tri` hoặc `ten: gia_tri`.
- FormatDetector: các cách viết khác gặp trong file cấu hình thực tế, ví dụ:

  - JSON / JavaScript / dict Python:  "password": "hunter22"
  - Mảng PHP:                         'db_password' => 'secret'
  - Hằng số PHP (WordPress):          define('AUTH_KEY', '...');
  - Thẻ XML (FileZilla, Maven, .NET): <Pass>...</Pass>, <password>...</password>
  - URL có kèm mật khẩu:              https://user:pass@host, ftp://u:p@h
  - File .netrc:                       machine x login y password z
  - Cấu hình dạng "khóa giá_trị":     password "abc"   (esmtp, ssh, nginx...)
  - File .pgpass:                      host:port:db:user:password
  - Mã băm mật khẩu crypt:            $6$salt$hash, $apr1$..., $2b$...
"""

import re


SENSITIVE_TOKENS = {
    "password",
    "passwd",
    "pwd",
    "passphrase",
    "secret",
    "token",
    "apikey",
    "credential",
    "credentials",
}

# "pass" là secret trong tên ghép (DB_PASS, ftp_pass, <Pass>) nhưng là
# từ thường trong văn xuôi ("Never pass ..."), nên đứng riêng chỉ được tính
# trong ngữ cảnh có cấu trúc (khóa JSON, thẻ XML).
COMPOUND_ONLY_TOKENS = {"pass"}

# "auth", "authorization" chỉ được tính khi là cả tên khóa trong
# ngữ cảnh có cấu trúc: "auth": "..." (Docker), "Authorization": "Bearer ...".
STRUCTURED_WHOLE_NAME_TOKENS = {"auth", "authorization"}

SENSITIVE_PAIRS = {
    ("api", "key"),
    ("private", "key"),
    ("secret", "key"),
    ("access", "key"),
    ("auth", "key"),
    ("client", "secret"),
    ("signing", "key"),
    ("encryption", "key"),
    ("master", "key"),
}

# Tên khóa chỉ mang thông tin mô tả, không phải secret.
NON_SECRET_TOKENS = {
    "field",
    "fields",
    "label",
    "placeholder",
    "hint",
    "prompt",
    "policy",
    "length",
    "min",
    "max",
    "validators",
    "validator",
    "reset",
    "forgot",
    "url",
    "uri",
    "path",
    "file",
    "type",
    "id",
    "name",
    "count",
    "expires",
    "expiry",
    "ttl",
    "enabled",
    "required",
    "encoding",
    "header",
    "username",
    "user",
    "login",
    "email",
    "host",
    "hostname",
    "port",
}


def split_name(name):
    """
    Tách tên biến/khóa thành các từ thường:
    "sshUserPassword" -> ["ssh", "user", "password"]
    "DB_PASS"         -> ["db", "pass"]
    """
    words = []

    for part in re.split(r"[^A-Za-z0-9]+", name):
        words.extend(
            re.findall(r"[A-Z]+(?![a-z])|[A-Z]?[a-z]+|\d+", part)
        )

    return [word.lower() for word in words if word]


def is_sensitive_name(name, extra_tokens=(), structured=False):
    """
    Kiểm tra tên khóa có cho thấy giá trị là secret không.

    structured=True khi tên lấy từ khóa JSON/dict hoặc thẻ XML,
    tức là chắc chắn là tên trường dữ liệu, không phải văn xuôi.
    """
    words = split_name(name)

    if not words:
        return False

    if words[-1] in NON_SECRET_TOKENS:
        return False

    if structured and len(words) == 1 and words[0] in (
        STRUCTURED_WHOLE_NAME_TOKENS | COMPOUND_ONLY_TOKENS
    ):
        return True

    if len(words) > 1 and any(word in COMPOUND_ONLY_TOKENS for word in words):
        return True

    tokens = SENSITIVE_TOKENS | set(extra_tokens)

    for word in words:
        if word in tokens:
            return True

        # Từ ghép viết liền: "dbpassword", "clientsecret", "passwords".
        if word.endswith(("password", "passwd", "passphrase", "apikey", "secret")):
            return True

        if word.startswith(("password", "passwd")):
            return True

    return any(
        (first, second) in SENSITIVE_PAIRS
        for first, second in zip(words, words[1:])
    )


class KeywordDetector:
    """
    Phát hiện thông tin bí mật dựa trên tên biến và từ khóa nhạy cảm.
    """

    def __init__(self, min_length=4, keyword_exclude=None):
        self.min_length = min_length

        # Các từ khóa liên quan đến thông tin bí mật.
        self.keywords = [
            "password",
            "passwd",
            "pwd",
            "secret",
            "api_key",
            "api-key",
            "auth_key",
            "auth-key",
            "access_token",
            "access-token",
            "auth_token",
            "auth-token",
            "refresh_token",
            "refresh-token",
            "client_secret",
            "client-secret",
            "private_key",
            "private-key",
            "database_password",
            "database-password",
            "db_password",
            "db-password",
            "service_key",
            "service-key",
            "credential",

            # Bổ sung các loại token thường gặp.
            "token",
            "jwt_token",
            "jwt-token",
            "bearer_token",
            "bearer-token",
            "session_token",
            "session-token",
            "oauth_token",
            "oauth-token",
            "id_token",
            "id-token",
            "private_token",
            "private-token",
        ]

        # Cho phép dấu gạch dưới và gạch ngang thay thế nhau.
        keyword_patterns = [
            re.escape(keyword).replace(r"\_", r"[\_-]")
            for keyword in self.keywords
        ]

        self.keyword_regex = re.compile(
            r"(?i)(?:" + "|".join(keyword_patterns) + r")"
        )

        # Nhận diện phép gán trong mã nguồn và file cấu hình.
        self.assignment_regex = re.compile(
            r"""
            (?P<name>
                [A-Za-z_][A-Za-z0-9_-]*
            )
            [ \t]*
            (?::=|=(?!=)|:(?!=))
            [ \t]*
            (?:
                (?P<quote>["'])
                (?P<quoted_value>[^"'\r\n]*)
                (?P=quote)
                |
                (?P<plain_value>[^\s,;#}\]]+)
            )
            """,
            re.VERBOSE,
        )

        # Những giá trị mẫu thường không phải secret thật.
        self.excluded_values = {
            "",
            "password",
            "your_password",
            "your_password_here",
            "changeme",
            "change_me",
            "example",
            "sample",
            "placeholder",
            "your_api_key",
            "your_api_key_here",
            "your_secret",
            "your_secret_here",
            "null",
            "none",
            "undefined",
        }

        self.keyword_exclude = [
            re.compile(pattern, re.IGNORECASE)
            for pattern in (keyword_exclude or [])
        ]

    def _is_secret_name(self, name):
        """Kiểm tra tên biến có chứa từ khóa nhạy cảm không."""
        words = split_name(name)

        if words and words[-1] in NON_SECRET_TOKENS:
            return False

        if self.keyword_regex.search(name):
            return True

        # Bổ sung các tên thường gặp trong file thực tế:
        # IRC_PASS, sshPassphrase, AUTH_SALT, apiKey...
        return is_sensitive_name(name)

    def _is_excluded(self, name, value):
        """Kiểm tra giá trị có thuộc trường hợp cần bỏ qua không."""
        normalized_value = value.strip().lower()

        if normalized_value in self.excluded_values:
            return True

        # Bỏ qua tham chiếu biến môi trường:
        # $API_KEY, ${DB_PASSWORD}, {{ API_KEY }}
        if re.fullmatch(
            r"\$\{?[A-Za-z_][A-Za-z0-9_]*\}?",
            value.strip(),
        ):
            return True

        if re.fullmatch(
            r"\{\{\s*[A-Za-z_][A-Za-z0-9_]*\s*\}\}",
            value.strip(),
        ):
            return True

        text_to_check = f"{name}={value}"

        for pattern in self.keyword_exclude:
            if pattern.search(text_to_check):
                return True

        return False

    def detect(self, text):
        """
        Phân tích văn bản và trả về danh sách phát hiện.
        """
        findings = []

        if not isinstance(text, str) or not text:
            return findings

        for match in self.assignment_regex.finditer(text):
            name = match.group("name")

            if not self._is_secret_name(name):
                continue

            quoted_value = match.group("quoted_value")
            plain_value = match.group("plain_value")

            if quoted_value is not None:
                secret_value = quoted_value
                start = match.start("quoted_value")
                end = match.end("quoted_value")
            else:
                secret_value = plain_value
                start = match.start("plain_value")
                end = match.end("plain_value")

            if secret_value is None:
                continue

            secret_value = secret_value.strip()

            if len(secret_value) < self.min_length:
                continue

            if self._is_excluded(name, secret_value):
                continue

            findings.append({
                "type": "Secret Keyword",
                "secret": secret_value,
                "start": start,
                "end": end,
                "keyword": name,
            })

        # Loại bỏ kết quả trùng vị trí.
        unique_findings = []
        seen = set()

        for finding in findings:
            key = (
                finding["start"],
                finding["end"],
                finding["secret"],
            )

            if key in seen:
                continue

            seen.add(key)
            unique_findings.append(finding)

        return unique_findings


class FormatDetector:
    """
    Phát hiện secret theo cấu trúc của các định dạng file phổ biến.
    """

    def __init__(self, min_length=4):
        self.min_length = min_length

        self.quoted_key_pattern = re.compile(
            r"""
            (?P<kq>["'])(?P<name>[A-Za-z_][A-Za-z0-9_.\- ]{0,60})(?P=kq)
            [ \t]*(?::|=>|=)[ \t]*
            (?P<vq>["'])(?P<value>(?:\\.|(?!(?P=vq))[^\\\r\n])*)(?P=vq)
            """,
            re.VERBOSE,
        )

        self.php_define_pattern = re.compile(
            r"""
            \bdefine\s*\(\s*
            (?P<nq>["'])(?P<name>[A-Za-z_][A-Za-z0-9_]*)(?P=nq)\s*,\s*
            (?P<vq>["'])(?P<value>(?:(?!(?P=vq))[^\r\n])*)(?P=vq)
            \s*\)
            """,
            re.VERBOSE | re.IGNORECASE,
        )

        self.xml_element_pattern = re.compile(
            r"<(?P<name>[A-Za-z_][\w.\-]*)(?:\s[^<>]*)?>"
            r"(?P<value>[^<>\r\n]+)"
            r"</(?P=name)>"
        )

        self.url_credentials_pattern = re.compile(
            r"\b[a-zA-Z][a-zA-Z0-9+.\-]{1,20}://"
            r"(?P<user>[^\s:/'\"`<>]*)"
            r":(?P<value>[^\s/'\"`<>]+)"
            r"@(?P<host>[A-Za-z0-9.\-\[\]]+)"
        )

        self.netrc_pattern = re.compile(
            r"\bmachine\s+\S+.*?\bpassword\s+(?P<value>\S+)",
            re.IGNORECASE,
        )

        self.keyword_value_pattern = re.compile(
            r"""^[ \t]*(?P<name>[A-Za-z_][\w.\-]*)[ \t]+
            (?P<vq>["'])(?P<value>[^"'\r\n]+)(?P=vq)[ \t]*;?[ \t]*$""",
            re.VERBOSE | re.MULTILINE,
        )

        self.pgpass_pattern = re.compile(
            r"^(?:[^:#\s]+|\*):(?:\d+|\*):[^:\s]+:[^:\s]+:(?P<value>[^:\s]+)$",
            re.MULTILINE,
        )

        self.crypt_hash_pattern = re.compile(
            r"(?<![A-Za-z0-9$])"
            r"\$(?:1|2[abxy]?|5|6|y|gy|7|apr1|sha1|md5)\$"
            r"(?:rounds=\d+\$)?"
            r"[./A-Za-z0-9]{1,64}\$[./A-Za-z0-9]{8,}"
        )

    @staticmethod
    def _value_is_template(value):
        stripped = value.strip()
        return bool(
            re.fullmatch(r"\$[A-Za-z_][A-Za-z0-9_]*", stripped)
            or re.fullmatch(r"\$\{[^}]+\}", stripped)
            or re.fullmatch(r"\{\{.*\}\}", stripped)
            or re.fullmatch(r"\{[A-Za-z_][A-Za-z0-9_.]*\}", stripped)
            or re.fullmatch(r"%\(?[A-Za-z_][A-Za-z0-9_]*\)?s?%?", stripped)
            or re.fullmatch(r"<[A-Za-z_ -]+>", stripped)
        )

    def _add(self, findings, secret_type, value, start, end, reason, name=None):
        value_stripped = value.strip()

        if len(value_stripped) < self.min_length:
            return

        if self._value_is_template(value_stripped):
            return

        finding = {
            "type": secret_type,
            "secret": value_stripped,
            "start": start,
            "end": end,
            "detector": "Format",
            "context_reason": reason,
            "quoted": True,
        }

        if name is not None:
            finding["keyword"] = name

        findings.append(finding)

    def detect(self, text, quoted_keys=True):
        findings = []

        if not isinstance(text, str) or not text:
            return findings

        quoted_matches = self.quoted_key_pattern.finditer(text) if quoted_keys else ()

        for match in quoted_matches:
            name = match.group("name")

            if is_sensitive_name(name, structured=True):
                self._add(
                    findings, "Secret Keyword", match.group("value"),
                    match.start("value"), match.end("value"),
                    f"Giá trị của khóa nhạy cảm \"{name}\" (JSON/dict/mảng)", name,
                )

        for match in self.php_define_pattern.finditer(text):
            name = match.group("name")

            if is_sensitive_name(name, extra_tokens={"key", "salt"}):
                self._add(
                    findings, "Secret Keyword", match.group("value"),
                    match.start("value"), match.end("value"),
                    f"Hằng số PHP define('{name}')", name,
                )

        for match in self.xml_element_pattern.finditer(text):
            name = match.group("name").split(":")[-1]

            if is_sensitive_name(name, structured=True):
                self._add(
                    findings, "Secret Keyword", match.group("value"),
                    match.start("value"), match.end("value"),
                    f"Nội dung thẻ XML <{name}>", name,
                )

        for match in self.url_credentials_pattern.finditer(text):
            self._add(
                findings, "Password", match.group("value"),
                match.start("value"), match.end("value"),
                "Mật khẩu nằm trong URL (user:pass@host)",
            )

        for match in self.netrc_pattern.finditer(text):
            self._add(
                findings, "Password", match.group("value"),
                match.start("value"), match.end("value"),
                "Mật khẩu trong file .netrc",
            )

        for match in self.keyword_value_pattern.finditer(text):
            name = match.group("name")

            if is_sensitive_name(name):
                self._add(
                    findings, "Secret Keyword", match.group("value"),
                    match.start("value"), match.end("value"),
                    f"Cấu hình dạng \"{name} <giá trị>\"", name,
                )

        for match in self.pgpass_pattern.finditer(text):
            self._add(
                findings, "Password", match.group("value"),
                match.start("value"), match.end("value"),
                "Mật khẩu trong file .pgpass (host:port:db:user:password)",
            )

        for match in self.crypt_hash_pattern.finditer(text):
            self._add(
                findings, "Password Hash", match.group(0),
                match.start(), match.end(),
                "Mã băm mật khẩu dạng crypt (shadow, htpasswd)",
            )

        unique = {}

        for finding in findings:
            key = (finding["start"], finding["end"], finding["secret"])
            unique.setdefault(key, finding)

        return list(unique.values())
