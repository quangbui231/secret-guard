
from pathlib import Path

from secret_guard.detectors.regex_detector import RegexDetector
from secret_guard.detectors.entropy_detector import EntropyDetector
from secret_guard.detectors.keyword_detector import KeywordDetector


class SecretScanner:
    """
    Bộ quét trung tâm của Secret Guard.

    Kết hợp nhiều detector để phát hiện các giá trị
    có khả năng là thông tin bí mật trong văn bản hoặc file.
    """

    def __init__(self):
        self.detectors = [
            RegexDetector(),
            EntropyDetector(),
            KeywordDetector(),
        ]

    def scan_text(self, text, filename="<memory>"):
        """
        Quét văn bản và tổng hợp kết quả từ các detector.

        Mỗi kết quả được bổ sung tên file và số dòng.
        """
        if not isinstance(text, str):
            raise TypeError("Nội dung cần quét phải là chuỗi.")

        findings = []

        for detector in self.detectors:
            detector_findings = detector.detect(text)

            for finding in detector_findings:
                result = finding.copy()

                start = result.get("start", 0)
                result["filename"] = filename
                result["line"] = text.count("\n", 0, start) + 1

                findings.append(result)

        # Sắp xếp kết quả theo vị trí xuất hiện trong văn bản.
        findings.sort(
            key=lambda item: (
                item.get("start", 0),
                item.get("end", 0),
                item.get("type", ""),
            )
        )

        return findings

    def scan_file(self, filepath):
        """
        Đọc và quét một file mã nguồn hoặc file cấu hình.
        """
        path = Path(filepath)

        if not path.is_file():
            raise FileNotFoundError(
                f"Không tìm thấy file: {path}"
            )

        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError as error:
            raise ValueError(
                f"Không thể đọc file bằng UTF-8: {path}"
            ) from error

        return self.scan_text(text, filename=str(path))
