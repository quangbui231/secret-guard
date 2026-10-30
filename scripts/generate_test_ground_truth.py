
import csv
import re
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
TEST_DIR = PROJECT_ROOT / "dataset" / "test"
OUTPUT_FILE = TEST_DIR / "ground_truth_test.csv"

# Các file Positive thông thường:
# Dòng 1 là comment, dòng 2-11 chứa 10 mẫu secret.
POSITIVE_LINE_RANGES = {
    "api_keys.py": range(2, 12),
    "passwords.py": range(2, 12),
    "tokens.py": range(2, 12),
    "database_credentials.py": range(2, 12),
    "other_secrets.py": range(2, 12),
}

# Tự động nhận diện dòng chứa dấu hiệu PEM Private Key.
PRIVATE_KEY_PATTERN = re.compile(
    r"-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----"
)


def is_meaningful_line(line):
    """Bỏ qua dòng trống và dòng comment."""
    stripped = line.strip()
    return bool(stripped) and not stripped.startswith("#")


def classify_line(category, filename, line_number, line):
    """
    Xác định nhãn Ground Truth cho từng dòng.
    Positive = 1: Có secret.
    Negative = 0: Không có secret.
    """

    if category == "negative":
        return 0, "No Secret"

    if filename == "private_keys.py":
        if PRIVATE_KEY_PATTERN.search(line):
            return 1, "Private Key"
        return 0, "No Secret"

    positive_lines = POSITIVE_LINE_RANGES.get(filename, range(0))

    if line_number in positive_lines:
        return 1, "Secret"

    return 0, "No Secret"


def generate():
    records = []

    for category in ("positive", "negative"):
        folder = TEST_DIR / category

        if not folder.exists():
            raise FileNotFoundError(
                f"Không tìm thấy thư mục: {folder}"
            )

        for file_path in sorted(folder.iterdir()):
            if not file_path.is_file():
                continue

            try:
                lines = file_path.read_text(
                    encoding="utf-8"
                ).splitlines()
            except UnicodeDecodeError:
                print(f"Skipped unreadable file: {file_path}")
                continue

            for line_number, line in enumerate(lines, start=1):
                if not is_meaningful_line(line):
                    continue

                expected, expected_type = classify_line(
                    category=category,
                    filename=file_path.name,
                    line_number=line_number,
                    line=line,
                )

                records.append({
                    "filename": f"{category}/{file_path.name}",
                    "line": line_number,
                    "expected_type": expected_type,
                    "expected_secret": expected,
                })

    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)

    with OUTPUT_FILE.open(
        "w",
        encoding="utf-8-sig",
        newline="",
    ) as csv_file:
        writer = csv.DictWriter(
            csv_file,
            fieldnames=[
                "filename",
                "line",
                "expected_type",
                "expected_secret",
            ],
        )
        writer.writeheader()
        writer.writerows(records)

    positive_count = sum(
        row["expected_secret"] == 1
        for row in records
    )
    negative_count = len(records) - positive_count

    print("=" * 55)
    print("SECRET GUARD - TEST GROUND TRUTH")
    print("=" * 55)
    print(f"Total records : {len(records)}")
    print(f"Positive      : {positive_count}")
    print(f"Negative      : {negative_count}")
    print(f"Output        : {OUTPUT_FILE}")

    print("\nPRIVATE KEY LABELS")
    print("-" * 55)

    for row in records:
        if (
            row["filename"] == "positive/private_keys.py"
            and row["expected_type"] == "Private Key"
        ):
            print(f"Line {row['line']}: {row['expected_type']}")

    print("=" * 55)


if __name__ == "__main__":
    generate()
