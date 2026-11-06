"""
Đánh giá Secret Guard trên bộ dữ liệu độc lập Plazmaz/leaky-repo.

leaky-repo (https://github.com/Plazmaz/leaky-repo) là repository cố ý chứa
secret giả trong nhiều loại file thực tế (.netrc, .pgpass, wp-config.php,
.docker/config.json, logins.json...). File .leaky-meta/secrets.csv do tác giả
repository gán nhãn số secret trong từng file, nên không phụ thuộc nhóm.

Chấm điểm giống hệt .leaky-meta/benchmark.py của leaky-repo:
    found     = số phát hiện trong file
    expected  = risk + informative
    FP        = max(found - expected, 0)
    finds     = tổng (found - FP)

Cách chạy:
    git clone https://github.com/Plazmaz/leaky-repo
    python -m evaluation.performance leaky-repo
    python -m evaluation.performance leaky-repo --compare   # thêm detect-secrets, gitleaks nếu đã cài
"""

import argparse
import csv
import json
import shutil
import subprocess
import tempfile
import time
from collections import Counter
from pathlib import Path

from secret_guard.main import SecretGuard


def expected_counts(repo):
    lines = []

    with open(repo / ".leaky-meta" / "secrets.csv", encoding="utf-8") as handle:
        lines = [line for line in handle if line.strip() and not line.startswith("#")]

    return [(row[0], int(row[1]), int(row[2])) for row in csv.reader(lines)]


def score(repo, found_by_file, label):
    rows = expected_counts(repo)
    total_found = total_expected = total_fp = covered = 0

    for name, risk, informative in rows:
        expected = risk + informative
        found = found_by_file.get(name, 0)
        false_positive = max(found - expected, 0)
        total_found += found - false_positive
        total_expected += expected
        total_fp += false_positive
        covered += found > 0

    return {
        "tool": label,
        "files_covered": f"{covered}/{len(rows)}",
        "finds": f"{total_found}/{total_expected}",
        "finds_pct": round(100 * total_found / total_expected, 1),
        "false_positives": total_fp,
    }


def run_secret_guard(repo):
    guard = SecretGuard(exclude_patterns=[".leaky-meta"])
    started = time.perf_counter()
    outcome = guard.scan_targets([repo])
    elapsed = time.perf_counter() - started

    all_findings, blocking = Counter(), Counter()

    for finding in outcome.findings:
        path = Path(finding["filename"].split("!")[0]).resolve()
        relative = path.relative_to(repo).as_posix()
        all_findings[relative] += 1

        if finding.get("action") == "BLOCK":
            blocking[relative] += 1

    return all_findings, blocking, elapsed


def run_detect_secrets(repo):
    if shutil.which("detect-secrets") is None:
        return None

    output = subprocess.run(
        ["detect-secrets", "scan", "--all-files", "."],
        cwd=repo, capture_output=True, text=True, check=False,
    ).stdout
    counts = Counter()

    for name, items in json.loads(output)["results"].items():
        if not name.startswith(".leaky-meta/"):
            counts[name] += len(items)

    return counts


def run_gitleaks(repo):
    if shutil.which("gitleaks") is None:
        return None

    with tempfile.TemporaryDirectory() as folder:
        report = Path(folder) / "gitleaks.json"
        subprocess.run(
            ["gitleaks", "dir", str(repo), "--no-banner", "--exit-code", "0", "-r", str(report)],
            capture_output=True, check=False,
        )
        items = json.loads(report.read_text(encoding="utf-8") or "[]")

    counts = Counter()

    for item in items:
        relative = Path(item["File"]).resolve().relative_to(repo).as_posix()

        if not relative.startswith((".leaky-meta/", ".git/")):
            counts[relative] += 1

    return counts


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    parser.add_argument("repo", help="Đường dẫn tới thư mục leaky-repo đã clone.")
    parser.add_argument("--compare", action="store_true", help="Chạy thêm detect-secrets và gitleaks nếu có.")
    parser.add_argument("--per-file", action="store_true", help="In kết quả từng file.")
    args = parser.parse_args()

    repo = Path(args.repo).resolve()
    all_findings, blocking, elapsed = run_secret_guard(repo)

    results = [
        score(repo, blocking, "Secret Guard (chỉ BLOCK)"),
        score(repo, all_findings, f"Secret Guard (BLOCK + REVIEW), {elapsed:.2f} giây"),
    ]

    if args.compare:
        for label, runner in (("detect-secrets", run_detect_secrets), ("gitleaks", run_gitleaks)):
            counts = runner(repo)
            results.append(
                score(repo, counts, label) if counts is not None
                else {"tool": label, "note": "chưa cài, bỏ qua"}
            )

    for result in results:
        print(json.dumps(result, ensure_ascii=False))

    if args.per_file:
        print()
        for name, risk, informative in expected_counts(repo):
            print(f"{name:42} expected={risk + informative:3} "
                  f"block={blocking.get(name, 0):3} all={all_findings.get(name, 0):3}")


if __name__ == "__main__":
    main()
