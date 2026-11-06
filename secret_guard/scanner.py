import re
from pathlib import PurePosixPath

from secret_guard.detectors.regex_detector import RegexDetector
from secret_guard.detectors.entropy_detector import EntropyDetector
from secret_guard.detectors.keyword_detector import FormatDetector, KeywordDetector
from secret_guard.detectors.python_context import PythonContextAnalyzer
from secret_guard.filters.file_filter import ARCHIVE_SEPARATOR, FileReader


# File mã nguồn: giá trị không có dấu nháy sau dấu "=" là biểu thức
# (biến, lời gọi hàm), không phải chuỗi secret viết thẳng.
# Không gồm shell, .env, .ini... vì ở đó giá trị không nháy là bình thường.
# Không gồm .py: với Python, PythonContextAnalyzer (AST) xử lý chính xác hơn,
# và cờ --no-python-context phải tái hiện đúng bản gốc để so sánh.
CODE_SUFFIXES = {
    ".pyw", ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".vue",
    ".svelte", ".java", ".kt", ".kts", ".scala", ".groovy", ".go", ".rb",
    ".php", ".cs", ".c", ".h", ".cc", ".cpp", ".hpp", ".swift", ".rs",
    ".dart", ".lua", ".m", ".r",
}

ASSIGNMENT_BEFORE_VALUE = re.compile(
    r"(?:^|[\s,{(;\[])[\"']?[A-Za-z_$][\w.$\-]*[\"']?\s*(?::=|=>|=|:)\s*$"
)

URL_BEFORE_VALUE = re.compile(r"://[^\s]*$")

# Giá trị không nháy mang hình dạng biểu thức code, thường gặp trong
# tài liệu .md/.rst: PasswordField(, request.form[, <input, form.password.data
EXPRESSION_VALUE = re.compile(r"^(?:[A-Za-z_][\w.]*[(\[]|<[A-Za-z/!])")
ATTRIBUTE_VALUE = re.compile(r"[A-Za-z_][A-Za-z_]*(?:\.[A-Za-z_][A-Za-z_]*)+")

UNQUOTED_TYPES = {"Secret Keyword", "Password", "API Key", "Token"}


class SecretScanner:
    """
    Bộ quét trung tâm của Secret Guard.

    Kết hợp nhiều detector để phát hiện các giá trị
    có khả năng là thông tin bí mật trong văn bản hoặc file.
    """

    def __init__(self, enable_python_context=True, file_reader=None):
        self.enable_python_context = enable_python_context
        self.python_context = PythonContextAnalyzer()
        self.file_reader = file_reader or FileReader()
        self.detectors = [
            RegexDetector(),
            EntropyDetector(),
            KeywordDetector(),
            FormatDetector(),
        ]

    @staticmethod
    def _inner_suffix(filename):
        """Đuôi của file thật, kể cả khi nằm trong file nén (a.zip!b/c.py)."""
        inner = str(filename).split(ARCHIVE_SEPARATOR)[-1].replace("\\", "/")
        return PurePosixPath(inner).suffix.lower()

    @staticmethod
    def _mark_quoted(text, finding):
        """
        Ghi nhận giá trị có nằm trong dấu nháy hay không,
        và có phải giá trị đứng ngay sau phép gán hay không.
        """
        start = finding.get("start", 0)
        line_start = text.rfind("\n", 0, start) + 1
        prefix = text[line_start:start]

        if "quoted" not in finding:
            finding["quoted"] = bool(prefix) and prefix[-1] in "\"'`"

        finding["unquoted_assignment"] = (
            not finding["quoted"]
            and bool(ASSIGNMENT_BEFORE_VALUE.search(prefix))
            and not URL_BEFORE_VALUE.search(prefix)
        )

    def _drop_code_expressions(self, findings, filename):
        """
        Trong file mã nguồn, `password = get_password()` hay
        `token = request.form["token"]` là biểu thức, không phải secret.

        File .py được giữ nguyên ở bước này vì đã có AST xử lý.
        """
        suffix = self._inner_suffix(filename)

        if suffix == ".py":
            return findings

        is_code = suffix in CODE_SUFFIXES
        kept = []

        for finding in findings:
            value = str(finding.get("secret", "")).strip()

            if finding.get("type") in UNQUOTED_TYPES and not finding.get("quoted"):
                if is_code and finding.get("unquoted_assignment"):
                    continue

                if EXPRESSION_VALUE.match(value) or ATTRIBUTE_VALUE.fullmatch(value):
                    continue

            kept.append(finding)

        return kept

    def scan_text(self, text, filename="<memory>"):
        """
        Quét văn bản và tổng hợp kết quả từ các detector.

        Mỗi kết quả được bổ sung tên file và số dòng.
        """
        if not isinstance(text, str):
            raise TypeError("Nội dung cần quét phải là chuỗi.")

        findings = []

        is_python = self._inner_suffix(filename) == ".py"

        for detector in self.detectors:
            if isinstance(detector, FormatDetector):
                # Với Python, dict được AST đọc chính xác hơn (giải mã \x50,
                # nối "a" "b"), nên bỏ quy tắc khóa có nháy của FormatDetector.
                detector_findings = detector.detect(text, quoted_keys=not is_python)
            else:
                detector_findings = detector.detect(text)

            for finding in detector_findings:
                result = finding.copy()

                start = result.get("start", 0)
                result["filename"] = filename
                result["line"] = text.count("\n", 0, start) + 1

                findings.append(result)

        if self.enable_python_context and self._inner_suffix(filename) == ".py":
            findings = self.python_context.refine(text, findings)
            for finding in findings:
                finding["filename"] = filename
                finding["line"] = text.count("\n", 0, finding.get("start", 0)) + 1

        for finding in findings:
            self._mark_quoted(text, finding)

        findings = self._drop_code_expressions(findings, filename)

        # Sắp xếp kết quả theo vị trí xuất hiện trong văn bản.
        findings.sort(
            key=lambda item: (
                item.get("start", 0),
                item.get("end", 0),
                item.get("type", ""),
            )
        )

        return findings

    def scan_file_detailed(self, filepath):
        """
        Đọc một file bất kỳ (văn bản, tài liệu, file nén) và quét.

        Returns:
            tuple: (danh sách phát hiện, ReadResult chứa các mục bị bỏ qua)
        """
        read_result = self.file_reader.read(filepath)
        findings = []

        for source in read_result.sources:
            findings.extend(self.scan_text(source.text, filename=source.name))

        return findings, read_result

    def scan_file(self, filepath):
        """
        Đọc và quét một file mã nguồn hoặc file cấu hình.

        Raises:
            FileNotFoundError: nếu file không tồn tại.
            ValueError: nếu file không có nội dung văn bản nào đọc được.
        """
        findings, read_result = self.scan_file_detailed(filepath)

        if not read_result.sources and read_result.skipped:
            reasons = "; ".join(item.reason for item in read_result.skipped)
            raise ValueError(f"Không thể đọc nội dung văn bản: {filepath} ({reasons})")

        return findings
