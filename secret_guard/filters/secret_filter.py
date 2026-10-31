
import re


class SecretFilter:
    """
    Lọc các phát hiện nhằm giảm false positive.
    Không tự phát hiện secret hoặc phân loại mức độ rủi ro.
    """

    DEFAULT_PLACEHOLDERS = {
        "",
        "password",
        "your_password",
        "your_password_here",
        "your_api_key",
        "your_api_key_here",
        "your_secret",
        "your_secret_here",
        "your_token",
        "your_token_here",
        "example",
        "sample",
        "placeholder",
        "changeme",
        "change_me",
        "replace_me",
        "replace_with_secret",
        "insert_secret_here",
        "todo",
        "null",
        "none",
        "undefined",
        "not_set",
        "xxxxxxxx",
        "xxxxxxxxxx",
    }

    VARIABLE_REFERENCE_PATTERNS = (
        r"\$[A-Za-z_][A-Za-z0-9_]*",
        r"\$\{[A-Za-z_][A-Za-z0-9_]*\}",
        r"\{\{\s*[A-Za-z_][A-Za-z0-9_]*\s*\}\}",
    )

    CODE_REFERENCE_PATTERN = re.compile(
        r"\b(?:"
        r"os\.getenv"
        r"|os\.environ(?:\.get)?"
        r"|environ\.get"
        r"|process\.env"
        r"|config\.get"
        r")\b",
        re.IGNORECASE,
    )

    PLACEHOLDER_PATTERN = re.compile(
        r"^(?:"
        r"your_[a-z0-9_]+"
        r"|replace_with_[a-z0-9_]+"
        r"|insert_[a-z0-9_]+_here"
        r"|change_me"
        r"|changeme"
        r"|todo"
        r"|not_set"
        r"|[*x]{3,}"
        r")$",
        re.IGNORECASE,
    )

    def __init__(
        self,
        min_length=4,
        excluded_patterns=None,
        placeholders=None,
    ):
        if not isinstance(min_length, int) or isinstance(min_length, bool):
            raise TypeError("min_length phải là số nguyên.")

        if min_length < 1:
            raise ValueError("min_length phải lớn hơn 0.")

        self.min_length = min_length

        self.placeholders = {
            value.lower()
            for value in self.DEFAULT_PLACEHOLDERS
        }

        if placeholders:
            self.placeholders.update(
                value.strip().lower()
                for value in placeholders
                if isinstance(value, str)
            )

        self.excluded_patterns = []

        for pattern in excluded_patterns or []:
            try:
                self.excluded_patterns.append(re.compile(pattern))
            except (TypeError, re.error) as error:
                raise ValueError(
                    f"Regex loại trừ không hợp lệ: {pattern!r}"
                ) from error

        self.variable_patterns = [
            re.compile(pattern)
            for pattern in self.VARIABLE_REFERENCE_PATTERNS
        ]

    def _should_exclude(self, finding):
        secret = finding.get("secret")

        if not isinstance(secret, str):
            return True

        value = secret.strip()

        if len(value) < self.min_length:
            return True

        normalized = value.lower()

        # Loại các placeholder đã biết.
        if normalized in self.placeholders:
            return True

        # Loại các placeholder theo mẫu, ví dụ YOUR_TOKEN_HERE.
        if self.PLACEHOLDER_PATTERN.fullmatch(value):
            return True

        # Loại các chuỗi tham chiếu biến như $API_KEY, ${API_KEY}.
        if any(
            pattern.fullmatch(value)
            for pattern in self.variable_patterns
        ):
            return True

        # Loại các biểu thức lấy giá trị từ biến môi trường/config.
        if not finding.get("literal_value") and self.CODE_REFERENCE_PATTERN.search(value):
            return True

        # Loại theo quy tắc tùy chỉnh.
        for pattern in self.excluded_patterns:
            if pattern.search(value):
                return True

        return False

    @staticmethod
    def _deduplication_key(finding):
        return (
            finding.get("filename"),
            finding.get("start"),
            finding.get("end"),
            finding.get("type"),
            finding.get("detector"),
            finding.get("secret"),
        )

    def filter_findings(self, findings):
        if not isinstance(findings, list):
            raise TypeError("findings phải là một list.")

        filtered = []
        seen = set()

        for finding in findings:
            if not isinstance(finding, dict):
                raise TypeError(
                    "Mỗi phát hiện phải là một dictionary."
                )

            if self._should_exclude(finding):
                continue

            key = self._deduplication_key(finding)

            if key in seen:
                continue

            seen.add(key)
            filtered.append(finding.copy())

        return filtered
