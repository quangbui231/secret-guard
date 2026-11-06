
import math
import re
import string
from collections import Counter


class EntropyDetector:
    """
    Phát hiện các chuỗi có độ ngẫu nhiên cao
    bằng Shannon entropy.
    """

    def __init__(
        self,
        base64_threshold=4.5,
        hex_threshold=3.0,
        generic_threshold=3.5,
        min_length=16,
    ):
        self.base64_threshold = base64_threshold
        self.hex_threshold = hex_threshold
        self.generic_threshold = generic_threshold
        self.min_length = min_length

        self.base64_charset = (
            string.ascii_letters
            + string.digits
            + "+/_-="
        )

        self.hex_charset = string.hexdigits

        self.base64_pattern = re.compile(
            r"(?<![A-Za-z0-9+/=_-])"
            r"[A-Za-z0-9+/_-]{16,}={0,2}"
            r"(?![A-Za-z0-9+/=_-])"
        )

        self.hex_pattern = re.compile(
            r"(?<![A-Fa-f0-9])"
            r"[A-Fa-f0-9]{16,}"
            r"(?![A-Fa-f0-9])"
        )

        self.generic_pattern = re.compile(
            r"(?<![A-Za-z0-9])"
            r"[A-Za-z0-9_+/=-]{16,}"
            r"(?![A-Za-z0-9])"
        )

        self.identifier_pattern = re.compile(
            r"^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+$"
        )

        self.assignment_pattern = re.compile(
            r"([A-Za-z_][A-Za-z0-9_]*)[\"']?\s*[:=]\s*"
            r"""["']?\s*$"""
        )

        # Tên biến cho biết giá trị là mã băm/phiên bản công khai,
        # ví dụ "rev: 57b2...", "integrity": "sha512-...".
        self.hash_name_keywords = {
            "rev",
            "revision",
            "sha",
            "sha1",
            "sha256",
            "sha384",
            "sha512",
            "md5",
            "hash",
            "checksum",
            "digest",
            "integrity",
            "commit",
            "etag",
            "fingerprint",
        }

        self.secret_keywords = {
            "secret",
            "key",
            "token",
            "password",
            "passwd",
            "credential",
            "credentials",
            "auth",
            "authentication",
            "private",
            "signing",
            "encryption",
            "webhook",
            "client",
            "api",
            "access",
            "refresh",
            "bearer",
            "oauth",
            "jwt",
        }

        self.identifier_keywords = {
            "id",
            "code",
            "reference",
            "identifier",
            "version",
            "description",
            "message",
            "region",
            "order",
            "customer",
            "product",
            "log",
            "file",
            "documentation",
            "doc",
        }

        self.private_key_pattern = re.compile(
            r"-----BEGIN (?:RSA |DSA |EC |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY(?: BLOCK)?-----"
            r".*?"
            r"-----END (?:RSA |DSA |EC |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY(?: BLOCK)?-----"
            r"|PuTTY-User-Key-File-\d+:.*?Private-MAC:[^\r\n]*",
            re.DOTALL,
        )

    def _remove_private_key_blocks(self, text):
        """
        Loại bỏ khối khóa (PEM, PuTTY) khỏi nội dung phân tích entropy.

        Giữ nguyên ký tự xuống dòng để số dòng không bị lệch.
        """

        return self.private_key_pattern.sub(
            lambda match: re.sub(r"[^\n]", " ", match.group(0)),
            text,
        )

    @staticmethod
    def _looks_like_words(candidate):
        """
        Chuỗi ghép từ các từ thông thường (tên hàm, hằng số, đường dẫn URL)
        thì không phải secret, dù entropy theo ký tự khá cao.

        Ví dụ bỏ qua: template_context_processors, RequestEntityTooLarge,
        org/en-US/docs/Web/API, my_custom_name_4.
        Ví dụ giữ lại: sk_live_9aF3kQ7mZ2xP8vL4, FAKE_TOKEN_82KLMN47.
        """
        tokens = []

        for part in re.split(r"[_\-/.+=:]+", candidate):
            if not part:
                continue

            pieces = re.findall(r"[A-Z]+(?![a-z])|[A-Z]?[a-z]+|\d+", part)

            if "".join(pieces) != part:
                return False

            tokens.extend(pieces)

        # Đường dẫn URL/file: mọi đoạn giữa dấu "/" đều là từ thường,
        # ví dụ org/dev/peps/pep-0519/, io/en/latest/Apache, /yourapplication.
        if "/" in candidate and all(
            re.fullmatch(r"[A-Za-z]+(?:[_\-.][A-Za-z0-9]+)*|\d+|", segment)
            for segment in candidate.split("/")
        ):
            return True

        # Một từ thường viết liền, toàn chữ thường hoặc toàn chữ hoa.
        if candidate.isalpha() and (candidate.islower() or candidate.isupper()):
            return True

        if len(tokens) < 2:
            return False

        digit_tokens = [token for token in tokens if token.isdigit()]
        alpha_tokens = [token for token in tokens if token.isalpha()]

        if len(digit_tokens) > 1 or any(len(token) > 4 for token in digit_tokens):
            return False

        if not alpha_tokens:
            return False

        short_tokens = sum(1 for token in alpha_tokens if len(token) <= 2)
        average = sum(len(token) for token in alpha_tokens) / len(alpha_tokens)

        return average >= 3.0 and short_tokens <= max(1, len(alpha_tokens) // 2)

    def _is_hash_context(self, text, position):
        """
        Giá trị gán cho tên như rev, sha256, integrity, checksum
        là mã băm công khai, không phải secret.
        """
        variable_name = self._get_variable_name(text, position)

        if not variable_name:
            return False

        words = set(re.split(r"[^a-z0-9]+", variable_name))

        if words & self.secret_keywords:
            return False

        return bool(words & self.hash_name_keywords)

    @staticmethod
    def _is_pinned_commit(candidate, text, position):
        """Mã commit gắn phiên bản sau '@', ví dụ actions/checkout@<sha>."""
        return (
            len(candidate) == 40
            and position > 0
            and text[position - 1] == "@"
            and all(character in string.hexdigits for character in candidate)
        )

    def _should_skip(self, candidate, text, position):
        return (
            self._looks_like_words(candidate)
            or self._is_hash_context(text, position)
            or self._is_pinned_commit(candidate, text, position)
        )

    def _is_identifier_like(self, candidate):
        """
        Kiểm tra chuỗi có cấu trúc giống mã định danh.
        """

        if not candidate:
            return False

        return (
            candidate == candidate.upper()
            and "_" in candidate
            and any(character.isdigit() for character in candidate)
            and bool(self.identifier_pattern.fullmatch(candidate))
        )

    def _get_variable_name(self, text, position):
        """
        Lấy tên biến đứng trước giá trị đang được phân tích
        trên cùng một dòng.
        """

        line_start = text.rfind("\n", 0, position) + 1
        prefix = text[line_start:position]

        match = self.assignment_pattern.search(prefix)

        if match:
            return match.group(1).lower()

        return ""

    def _is_normal_identifier_context(self, candidate, text, position):
        """
        Chỉ loại chuỗi giống mã định danh khi tên biến
        thể hiện rõ ngữ cảnh định danh thông thường.

        Nếu tên biến có từ khóa liên quan đến secret,
        không loại chuỗi.
        """

        if not self._is_identifier_like(candidate):
            return False

        variable_name = self._get_variable_name(
            text,
            position,
        )

        if not variable_name:
            return False

        words = set(
            re.split(r"[^a-z0-9]+", variable_name)
        )

        if words & self.secret_keywords:
            return False

        return bool(words & self.identifier_keywords)

    def calculate_entropy(self, data):
        if not data:
            return 0.0

        entropy = 0.0
        length = len(data)
        counts = Counter(data)

        for count in counts.values():
            probability = count / length
            entropy -= probability * math.log2(probability)

        return entropy

    def calculate_charset_entropy(self, data, charset):
        if not data:
            return 0.0

        entropy = 0.0
        length = len(data)

        for character in charset:
            count = data.count(character)

            if count == 0:
                continue

            probability = count / length
            entropy -= probability * math.log2(probability)

        return entropy

    def adjust_numeric_entropy(self, data, entropy):
        if len(data) <= 1:
            return entropy

        if not data.isdigit():
            return entropy

        adjustment = 1.2 / math.log2(len(data))

        return max(entropy - adjustment, 0.0)

    def analyze_candidate(
        self,
        candidate,
        secret_type,
        charset,
        threshold,
        start,
        end,
    ):
        if len(candidate) < self.min_length:
            return None

        entropy = self.calculate_charset_entropy(
            candidate,
            charset,
        )

        entropy = self.adjust_numeric_entropy(
            candidate,
            entropy,
        )

        if entropy <= threshold:
            return None

        return {
            "type": secret_type,
            "secret": candidate,
            "entropy": round(entropy, 4),
            "threshold": threshold,
            "start": start,
            "end": end,
        }

    def detect_base64(self, text):
        findings = []

        for match in self.base64_pattern.finditer(text):
            candidate = match.group(0)

            if self._should_skip(candidate, text, match.start()):
                continue

            finding = self.analyze_candidate(
                candidate=candidate,
                secret_type="Base64 High Entropy String",
                charset=self.base64_charset,
                threshold=self.base64_threshold,
                start=match.start(),
                end=match.end(),
            )

            if finding is not None:
                findings.append(finding)

        return findings

    def detect_hex(self, text):
        findings = []

        for match in self.hex_pattern.finditer(text):
            candidate = match.group(0)

            if self._is_hash_context(text, match.start()):
                continue

            # Mã commit gắn phiên bản: uses: actions/checkout@<sha>
            if self._is_pinned_commit(candidate, text, match.start()):
                continue

            finding = self.analyze_candidate(
                candidate=candidate,
                secret_type="Hex High Entropy String",
                charset=self.hex_charset,
                threshold=self.hex_threshold,
                start=match.start(),
                end=match.end(),
            )

            if finding is not None:
                findings.append(finding)

        return findings

    def detect_generic(self, text):
        findings = []

        for match in self.generic_pattern.finditer(text):
            candidate = match.group(0)
            start = match.start()

            # "TEN=gia_tri": chỉ phân tích phần giá trị, phần tên do
            # KeywordDetector xử lý.
            equal_sign = candidate.find("=")

            if 0 < equal_sign < len(candidate.rstrip("=")):
                candidate = candidate[equal_sign + 1:]
                start += equal_sign + 1

                if len(candidate) < self.min_length:
                    continue

            if candidate.isdigit():
                continue

            if self._should_skip(candidate, text, start):
                continue

            if self._is_normal_identifier_context(
                candidate,
                text,
                match.start(),
            ):
                continue

            entropy = self.calculate_entropy(candidate)

            if entropy < self.generic_threshold:
                continue

            findings.append({
                "type": "High Entropy",
                "secret": candidate,
                "entropy": round(entropy, 4),
                "threshold": self.generic_threshold,
                "start": start,
                "end": match.end(),
            })

        return findings

    def detect(self, text):
        findings = []

        if not isinstance(text, str) or not text:
            return findings

        text_to_analyze = self._remove_private_key_blocks(text)

        findings.extend(
            self.detect_base64(text_to_analyze)
        )

        findings.extend(
            self.detect_hex(text_to_analyze)
        )

        findings.extend(
            self.detect_generic(text_to_analyze)
        )

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
