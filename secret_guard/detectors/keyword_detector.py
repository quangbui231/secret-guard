
import re


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
            \s*
            (?::=|=(?!=)|:(?!=))
            \s*
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
        return bool(self.keyword_regex.search(name))

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
