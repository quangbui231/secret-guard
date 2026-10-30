
import argparse
import sys
from pathlib import Path

from secret_guard.scanner import SecretScanner
from secret_guard.filters.secret_filter import SecretFilter
from secret_guard.filters.allowlist import Allowlist
from secret_guard.policy.policy_engine import PolicyEngine
from secret_guard.reporting.reporter import Reporter
from secret_guard.reporting.masker import SecretMasker
from secret_guard.config import Config


class SecretGuard:
    """
    Điều phối toàn bộ quy trình quét và xử lý secret.
    """

    EXCLUDED_DIRECTORIES = {
        ".git",
        ".venv",
        "venv",
        "__pycache__",
        ".pytest_cache",
        "node_modules",
    }

    EXCLUDED_SUFFIXES = {
        ".pyc",
        ".pyo",
    }

    # Mức độ ưu tiên khi nhiều detector cùng phát hiện
    # một secret tại cùng vị trí.
    TYPE_PRIORITY = {
        "Private Key": 1,
        "API Key": 2,
        "Password": 3,
        "Token": 4,
        "Secret Keyword": 5,
        "Base64 High Entropy String": 6,
        "Hex High Entropy String": 7,
        "High Entropy": 8,
    }

    # Chuyển loại phát hiện thành tên detector.
    DETECTOR_NAMES = {
        "Private Key": "Regex",
        "API Key": "Regex",
        "Password": "Regex",
        "Token": "Regex",
        "Secret Keyword": "Keyword",
        "Base64 High Entropy String": "Entropy",
        "Hex High Entropy String": "Entropy",
        "High Entropy": "Entropy",
    }

    def __init__(self):
        self.config = Config()

        self.scanner = SecretScanner()

        self.secret_filter = SecretFilter(
            min_length=self.config.min_secret_length
        )

        self.allowlist = Allowlist(
            config_path=self.config.allowlist_path
        )

        self.policy_engine = PolicyEngine()

        self.masker = SecretMasker(
            visible_start=self.config.mask_visible_start,
            visible_end=self.config.mask_visible_end,
        )

        self.reporter = Reporter(masker=self.masker)

    def _collect_files(self, target):
        """
        Thu thập các file cần quét từ file hoặc thư mục.
        """
        path = Path(target).resolve()

        if not path.exists():
            raise FileNotFoundError(
                f"Không tìm thấy đường dẫn: {path}"
            )

        if path.is_file():
            return [path]

        files = []

        for file_path in path.rglob("*"):
            if not file_path.is_file():
                continue

            relative_parts = file_path.relative_to(path).parts

            if any(
                part in self.EXCLUDED_DIRECTORIES
                for part in relative_parts
            ):
                continue

            if file_path.suffix.lower() in self.EXCLUDED_SUFFIXES:
                continue

            files.append(file_path)

        return sorted(files)

    def _merge_findings(self, findings):
        """
        Gộp các phát hiện trùng nhau từ nhiều detector.

        Hai phát hiện được xem là trùng nhau khi có cùng:
        - Tên file.
        - Vị trí bắt đầu.
        - Vị trí kết thúc.
        - Giá trị secret.

        Giữ lại loại phát hiện cụ thể nhất và ghi nhận
        tất cả detector đã phát hiện secret đó.
        """
        merged = {}

        for finding in findings:
            key = (
                finding.get("filename"),
                finding.get("start"),
                finding.get("end"),
                finding.get("secret"),
            )

            if key not in merged:
                merged[key] = finding.copy()
                merged[key]["detected_by"] = []

            original_type = finding.get("type", "")

            detector_name = self.DETECTOR_NAMES.get(
                original_type,
                "Unknown",
            )

            if detector_name not in merged[key]["detected_by"]:
                merged[key]["detected_by"].append(detector_name)

            current_type = merged[key].get("type", "")

            current_priority = self.TYPE_PRIORITY.get(
                current_type,
                999,
            )

            new_priority = self.TYPE_PRIORITY.get(
                original_type,
                999,
            )

            # Giữ lại loại phát hiện có mức ưu tiên cao hơn.
            if new_priority < current_priority:
                merged[key]["type"] = original_type

            # Bổ sung thông tin entropy nếu phát hiện mới có.
            if "entropy" in finding:
                merged[key]["entropy"] = finding["entropy"]

            if "threshold" in finding:
                merged[key]["threshold"] = finding["threshold"]

        results = list(merged.values())

        results.sort(
            key=lambda item: (
                item.get("filename", ""),
                item.get("start", 0),
                item.get("end", 0),
            )
        )

        return results

    def scan_path(self, target):
        """
        Quét file hoặc toàn bộ file trong thư mục.
        """
        files = self._collect_files(target)

        all_findings = []
        skipped_files = 0

        print(f"\nScanning: {Path(target).resolve()}")
        print(f"Files to scan: {len(files)}")
        print("-" * 60)

        for file_path in files:
            try:
                findings = self.scanner.scan_file(file_path)
                all_findings.extend(findings)

            except (UnicodeDecodeError, ValueError):
                skipped_files += 1
                continue

            except OSError:
                skipped_files += 1
                continue

        # Bước 1: Loại bỏ placeholder và giá trị không phù hợp.
        filtered_findings = self.secret_filter.filter_findings(
            all_findings
        )

        # Bước 2: Loại bỏ các phát hiện nằm trong allowlist.
        allowed_findings = self.allowlist.filter_findings(
            filtered_findings
        )

        # Bước 3: Gộp các phát hiện trùng nhau từ nhiều detector.
        merged_findings = self._merge_findings(
            allowed_findings
        )

        # Bước 4: Đánh giá mức độ rủi ro và hành động xử lý.
        evaluated_findings = self.policy_engine.evaluate(
            merged_findings
        )

        summary = self.policy_engine.summarize(
            evaluated_findings
        )

        # Hiển thị báo cáo.
        self.reporter.print_report(evaluated_findings)

        print("\nSCAN SUMMARY")
        print("-" * 60)
        print(f"Files scanned: {len(files) - skipped_files}")
        print(f"Files skipped: {skipped_files}")
        print(f"Raw findings: {len(all_findings)}")
        print(f"After filtering: {len(filtered_findings)}")
        print(f"After allowlist: {len(allowed_findings)}")
        print(f"After merging: {len(merged_findings)}")
        print(f"Total findings: {summary['total']}")
        print(f"BLOCK: {summary['by_action']['BLOCK']}")
        print(f"REVIEW: {summary['by_action']['REVIEW']}")

        return evaluated_findings

    def run(self, target):
        findings = self.scan_path(target)

        # Trả về mã lỗi nếu có phát hiện cần BLOCK.
        has_blocking_findings = any(
            finding.get("action") == "BLOCK"
            for finding in findings
        )

        return 1 if has_blocking_findings else 0


def main():
    parser = argparse.ArgumentParser(
        description="Secret Guard - Source Code Secret Scanner"
    )

    parser.add_argument(
        "target",
        help="Đường dẫn file hoặc thư mục cần quét.",
    )

    args = parser.parse_args()

    try:
        guard = SecretGuard()
        exit_code = guard.run(args.target)
        sys.exit(exit_code)

    except (
        FileNotFoundError,
        ValueError,
        TypeError,
        RuntimeError,
    ) as error:
        print(f"Error: {error}", file=sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    main()
