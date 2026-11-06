import argparse
import fnmatch
import json
import os
import subprocess
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from secret_guard.scanner import SecretScanner
from secret_guard.filters.file_filter import MB, FileReader, SkippedItem
from secret_guard.filters.secret_filter import SecretFilter
from secret_guard.filters.allowlist import Allowlist
from secret_guard.policy.policy_engine import PolicyEngine
from secret_guard.reporting.reporter import Reporter
from secret_guard.reporting.masker import SecretMasker
from secret_guard.config import Config


class ScanOutcome:
    """Kết quả một lần quét: phát hiện cuối cùng và số liệu từng bước."""

    def __init__(self):
        self.targets = []
        self.findings = []
        self.files_total = 0
        self.files_read = 0
        self.text_sources = 0
        self.skipped = []
        self.excluded = 0
        self.counts = {}
        self.summary = {}

    def skipped_by_reason(self):
        counter = Counter()

        for item in self.skipped:
            reason = item.reason.split(" (")[0]
            counter[reason] += 1

        return counter


class SecretGuard:
    """
    Điều phối toàn bộ quy trình quét và xử lý secret.
    """

    # Thư mục phụ thuộc, bộ nhớ đệm và kết quả build: không chứa mã
    # do nhóm phát triển viết, lại rất lớn và gây nhiều báo nhầm.
    EXCLUDED_DIRECTORIES = {
        ".git",
        ".hg",
        ".svn",
        ".venv",
        "venv",
        "__pycache__",
        ".pytest_cache",
        ".mypy_cache",
        ".ruff_cache",
        ".tox",
        ".nox",
        ".eggs",
        "node_modules",
        "bower_components",
        ".next",
        ".nuxt",
        ".gradle",
        ".terraform",
        "dist",
        "build",
        "target",
        "htmlcov",
        "coverage",
    }

    # File sinh tự động chứa hàng nghìn mã băm công khai.
    EXCLUDED_FILE_PATTERNS = {
        "package-lock.json",
        "npm-shrinkwrap.json",
        "yarn.lock",
        "pnpm-lock.yaml",
        "poetry.lock",
        "Pipfile.lock",
        "uv.lock",
        "pdm.lock",
        "Cargo.lock",
        "composer.lock",
        "Gemfile.lock",
        "go.sum",
        "packages.lock.json",
        "*.min.js",
        "*.min.css",
        "*.map",
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
        "Password Hash": 4,
        "Token": 5,
        "Secret Keyword": 6,
        "Base64 High Entropy String": 7,
        "Hex High Entropy String": 8,
        "High Entropy": 9,
    }

    # Chuyển loại phát hiện thành tên detector.
    DETECTOR_NAMES = {
        "Private Key": "Regex",
        "API Key": "Regex",
        "Password": "Regex",
        "Password Hash": "Format",
        "Token": "Regex",
        "Secret Keyword": "Keyword",
        "Base64 High Entropy String": "Entropy",
        "Hex High Entropy String": "Entropy",
        "High Entropy": "Entropy",
    }

    def __init__(
        self,
        enable_python_context=True,
        max_file_size_mb=10,
        scan_archives=True,
        scan_documents=True,
        exclude_patterns=None,
        use_default_excludes=True,
        respect_gitignore=False,
    ):
        self.config = Config()

        self.file_reader = FileReader(
            max_file_size=int(max_file_size_mb * MB),
            scan_archives=scan_archives,
            scan_documents=scan_documents,
        )

        self.scanner = SecretScanner(
            enable_python_context=enable_python_context,
            file_reader=self.file_reader,
        )

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

        self.exclude_patterns = list(exclude_patterns or [])
        self.use_default_excludes = use_default_excludes
        self.respect_gitignore = respect_gitignore
        self._excluded_count = 0

    # ------------------------------------------------------------------
    # Thu thập file
    # ------------------------------------------------------------------

    def _matches_custom_pattern(self, relative_path):
        name = relative_path.split("/")[-1]

        for pattern in self.exclude_patterns:
            pattern = pattern.replace("\\", "/").strip("/")

            if (
                fnmatch.fnmatch(relative_path, pattern)
                or fnmatch.fnmatch(name, pattern)
                or relative_path.startswith(pattern + "/")
            ):
                return True

        return False

    def _is_excluded_directory(self, relative_path):
        """
        Thư mục bị loại thì không đi vào bên trong (nhanh với node_modules).
        """
        name = relative_path.split("/")[-1]

        if self.use_default_excludes and (
            name in self.EXCLUDED_DIRECTORIES or name.endswith(".egg-info")
        ):
            return True

        return self._matches_custom_pattern(relative_path)

    def _is_excluded(self, relative_path):
        """
        Kiểm tra đường dẫn tương đối (dạng a/b/c.py) có bị loại trừ không.
        """
        parts = relative_path.split("/")
        name = parts[-1]

        if any(
            self._is_excluded_directory("/".join(parts[: index + 1]))
            for index in range(len(parts) - 1)
        ):
            return True

        if self.use_default_excludes and any(
            fnmatch.fnmatch(name, pattern)
            for pattern in self.EXCLUDED_FILE_PATTERNS
        ):
            return True

        if Path(name).suffix.lower() in self.EXCLUDED_SUFFIXES:
            return True

        return self._matches_custom_pattern(relative_path)

    @staticmethod
    def _git_visible_files(directory):
        """
        Danh sách file git không bỏ qua (đã theo dõi + chưa theo dõi
        nhưng không nằm trong .gitignore). Trả về None nếu không dùng được git.
        """
        try:
            completed = subprocess.run(
                ["git", "-C", str(directory), "ls-files", "-z",
                 "--cached", "--others", "--exclude-standard"],
                capture_output=True,
                check=True,
                timeout=120,
            )
        except (OSError, subprocess.SubprocessError):
            return None

        return {
            (directory / name).resolve()
            for name in completed.stdout.decode("utf-8", "replace").split("\0")
            if name
        }

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

        git_files = None

        if self.respect_gitignore:
            git_files = self._git_visible_files(path)

            if git_files is None:
                print(
                    "Warning: không dùng được git, bỏ qua tùy chọn --respect-gitignore.",
                    file=sys.stderr,
                )

        files = []

        for root, directories, filenames in os.walk(path):
            root_path = Path(root)
            relative_root = root_path.relative_to(path).as_posix()
            prefix = "" if relative_root == "." else relative_root + "/"

            # Cắt bỏ thư mục bị loại ngay tại chỗ: os.walk sẽ không đi vào.
            kept = []

            for directory in sorted(directories):
                if self._is_excluded_directory(prefix + directory):
                    self._excluded_count += 1
                else:
                    kept.append(directory)

            directories[:] = kept

            for filename in filenames:
                file_path = root_path / filename

                if file_path.is_symlink() or not file_path.is_file():
                    continue

                if self._is_excluded(prefix + filename):
                    self._excluded_count += 1
                    continue

                if git_files is not None and file_path.resolve() not in git_files:
                    self._excluded_count += 1
                    continue

                files.append(file_path)

        return sorted(files)

    # ------------------------------------------------------------------
    # Gộp phát hiện
    # ------------------------------------------------------------------

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

            detector_name = finding.get("detector") or self.DETECTOR_NAMES.get(
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
            if "context_reason" in finding and not merged[key].get("context_reason"):
                merged[key]["context_reason"] = finding["context_reason"]

        results = self._fold_overlapping_entropy(list(merged.values()))

        results.sort(
            key=lambda item: (
                item.get("filename", ""),
                item.get("start", 0),
                item.get("end", 0),
            )
        )

        return results

    ENTROPY_TYPES = {
        "Base64 High Entropy String",
        "Hex High Entropy String",
        "High Entropy",
    }

    def _fold_overlapping_entropy(self, findings):
        """
        Phát hiện entropy chồng lên một phát hiện cụ thể hơn (cùng file)
        được gộp vào phát hiện đó, thay vì báo thêm một dòng REVIEW trùng.
        """
        specific = [
            item for item in findings
            if item.get("type") not in self.ENTROPY_TYPES
        ]
        results = list(specific)

        for item in findings:
            if item.get("type") not in self.ENTROPY_TYPES:
                continue

            host = next(
                (
                    other for other in specific
                    if other.get("filename") == item.get("filename")
                    and other.get("start", 0) < item.get("end", 0)
                    and item.get("start", 0) < other.get("end", 0)
                ),
                None,
            )

            if host is None:
                results.append(item)
            elif "Entropy" not in host["detected_by"]:
                host["detected_by"].append("Entropy")

        return results

    # ------------------------------------------------------------------
    # Quét
    # ------------------------------------------------------------------

    def scan_targets(self, targets):
        """
        Quét một hoặc nhiều file/thư mục, không in gì ra màn hình.

        Returns:
            ScanOutcome
        """
        if isinstance(targets, (str, Path)):
            targets = [targets]

        outcome = ScanOutcome()
        self._excluded_count = 0
        all_findings = []
        files = []

        for target in targets:
            outcome.targets.append(str(Path(target).resolve()))
            files.extend(self._collect_files(target))

        outcome.files_total = len(files)
        outcome.excluded = self._excluded_count

        for file_path in files:
            try:
                findings, read_result = self.scanner.scan_file_detailed(file_path)
            except OSError as error:
                outcome.skipped.append(SkippedItem(str(file_path), f"lỗi đọc file ({error})"))
                continue

            all_findings.extend(findings)
            outcome.skipped.extend(read_result.skipped)
            outcome.text_sources += len(read_result.sources)

            if read_result.sources:
                outcome.files_read += 1

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

        outcome.findings = evaluated_findings
        outcome.summary = self.policy_engine.summarize(evaluated_findings)
        outcome.counts = {
            "raw": len(all_findings),
            "after_filtering": len(filtered_findings),
            "after_allowlist": len(allowed_findings),
            "after_merging": len(merged_findings),
        }

        return outcome

    def print_summary(self, outcome, show_skipped=False):
        print("\nSCAN SUMMARY")
        print("-" * 60)
        print(f"Files found: {outcome.files_total}")
        print(f"Files scanned: {outcome.files_read}")
        print(f"Files skipped: {outcome.files_total - outcome.files_read}")

        if outcome.excluded:
            print(f"Excluded by rules (files/folders): {outcome.excluded}")

        reasons = outcome.skipped_by_reason()

        if reasons:
            print("Skipped items by reason:")
            for reason, count in reasons.most_common():
                print(f"  - {reason}: {count}")

        if show_skipped and outcome.skipped:
            print("Skipped items:")
            for item in outcome.skipped:
                print(f"  - {item.name}: {item.reason}")

        print(f"Raw findings: {outcome.counts['raw']}")
        print(f"After filtering: {outcome.counts['after_filtering']}")
        print(f"After allowlist: {outcome.counts['after_allowlist']}")
        print(f"After merging: {outcome.counts['after_merging']}")
        print(f"Total findings: {outcome.summary['total']}")
        print(f"BLOCK: {outcome.summary['by_action']['BLOCK']}")
        print(f"REVIEW: {outcome.summary['by_action']['REVIEW']}")

    def scan_path(self, target):
        """
        Quét file hoặc toàn bộ file trong thư mục và in báo cáo.
        """
        outcome = self.scan_targets([target])

        print(f"\nScanning: {Path(target).resolve()}")
        print(f"Files to scan: {outcome.files_total}")
        print("-" * 60)

        self.reporter.print_report(outcome.findings)
        self.print_summary(outcome)

        return outcome.findings

    def build_json_report(self, outcome, only_block=False):
        findings = [
            finding for finding in outcome.findings
            if not only_block or finding.get("action") == "BLOCK"
        ]

        return {
            "tool": "Secret Guard",
            "scanned_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "targets": outcome.targets,
            "summary": {
                "files_found": outcome.files_total,
                "files_scanned": outcome.files_read,
                "files_skipped": outcome.files_total - outcome.files_read,
                "excluded_by_rules": outcome.excluded,
                "skipped_by_reason": dict(outcome.skipped_by_reason()),
                **outcome.counts,
                "total_findings": outcome.summary["total"],
                "block": outcome.summary["by_action"]["BLOCK"],
                "review": outcome.summary["by_action"]["REVIEW"],
            },
            "findings": [self.reporter.to_dict(finding) for finding in findings],
            "skipped": [
                {"file": item.name, "reason": item.reason}
                for item in outcome.skipped
            ],
        }

    @staticmethod
    def exit_code(findings):
        has_blocking_findings = any(
            finding.get("action") == "BLOCK"
            for finding in findings
        )

        return 1 if has_blocking_findings else 0

    def run(self, target):
        findings = self.scan_path(target)

        # Trả về mã lỗi nếu có phát hiện cần BLOCK.
        return self.exit_code(findings)


def build_parser():
    parser = argparse.ArgumentParser(
        prog="python -m secret_guard.main",
        description=(
            "Secret Guard - quét thông tin bí mật trong file, thư mục, "
            "tài liệu Office/PDF, notebook và file nén."
        ),
    )

    parser.add_argument(
        "targets",
        nargs="+",
        help="Một hoặc nhiều file/thư mục cần quét.",
    )
    parser.add_argument(
        "--exclude",
        action="append",
        default=[],
        metavar="PATTERN",
        help="Bỏ qua file/thư mục khớp mẫu glob (dùng nhiều lần được), ví dụ --exclude tests --exclude '*.csv'.",
    )
    parser.add_argument(
        "--no-default-excludes",
        action="store_true",
        help="Quét cả node_modules, dist, build, lock file... (mặc định bỏ qua).",
    )
    parser.add_argument(
        "--respect-gitignore",
        action="store_true",
        help="Chỉ quét file mà git không bỏ qua (dùng .gitignore của repo).",
    )
    parser.add_argument(
        "--max-file-size",
        type=float,
        default=10,
        metavar="MB",
        help="Bỏ qua file lớn hơn mức này (mặc định 10 MB).",
    )
    parser.add_argument(
        "--no-archives",
        action="store_true",
        help="Không mở file nén (zip, tar, gz...).",
    )
    parser.add_argument(
        "--no-documents",
        action="store_true",
        help="Không trích văn bản từ Word, Excel, PowerPoint, PDF.",
    )
    parser.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="Định dạng báo cáo (mặc định text).",
    )
    parser.add_argument(
        "--output",
        metavar="FILE",
        help="Ghi báo cáo ra file thay vì màn hình.",
    )
    parser.add_argument(
        "--only-block",
        action="store_true",
        help="Chỉ hiện phát hiện mức BLOCK (mã thoát không đổi).",
    )
    parser.add_argument(
        "--show-skipped",
        action="store_true",
        help="Liệt kê từng file bị bỏ qua kèm lý do.",
    )
    parser.add_argument(
        "--no-python-context",
        action="store_true",
        help="Tắt phân tích ngữ cảnh Python (AST) để so sánh với bản gốc.",
    )

    return parser


def main(argv=None):
    # Tránh lỗi khi in tiếng Việt ra file/pipe trên Windows (cp1252).
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            try:
                stream.reconfigure(errors="replace")
            except (ValueError, OSError):
                pass

    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        guard = SecretGuard(
            enable_python_context=not args.no_python_context,
            max_file_size_mb=args.max_file_size,
            scan_archives=not args.no_archives,
            scan_documents=not args.no_documents,
            exclude_patterns=args.exclude,
            use_default_excludes=not args.no_default_excludes,
            respect_gitignore=args.respect_gitignore,
        )

        outcome = guard.scan_targets(args.targets)
        shown = [
            finding for finding in outcome.findings
            if not args.only_block or finding.get("action") == "BLOCK"
        ]

        if args.format == "json":
            report = json.dumps(
                guard.build_json_report(outcome, only_block=args.only_block),
                ensure_ascii=False,
                indent=2,
            )

            if args.output:
                Path(args.output).write_text(report + "\n", encoding="utf-8")
                print(f"Đã ghi báo cáo JSON: {Path(args.output).resolve()}")
            else:
                print(report)
        else:
            if args.output:
                text = guard.reporter.generate_report(shown)
                Path(args.output).write_text(text + "\n", encoding="utf-8")
                print(f"Đã ghi báo cáo: {Path(args.output).resolve()}")
            else:
                for target in outcome.targets:
                    print(f"\nScanning: {target}")
                print(f"Files to scan: {outcome.files_total}")
                print("-" * 60)
                guard.reporter.print_report(shown)

            guard.print_summary(outcome, show_skipped=args.show_skipped)

        sys.exit(guard.exit_code(outcome.findings))

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
