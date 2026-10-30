import csv
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATASET_DIR = PROJECT_ROOT / "dataset"
OUTPUT_FILE = DATASET_DIR / "ground_truth.csv"


# Các dòng đã xác định có chứa secret giả lập.
# Cấu trúc: filename: {line_number: (secret_type, expected_value)}
POSITIVE_LABELS = {
    "positive/api_keys.py": {
        2: ("API Key", "sk_test_7Fh92KxP4mN8vQ3rT6yW"),
        3: ("API Key", "AIzaSyDUMMY7Fh92KxP4mN8vQ3"),
        4: ("API Key", "AKIAIOSFODNN7EXAMPLE"),
    },
    "positive/database_credentials.py": {
        2: ("Password", "PgSQL_Prod!2026_Dummy"),
        3: ("Password", "M0ngoDB!Secure_Example"),
        4: ("Password", "RedisPass#2026_Test"),
        7: ("Database Password", "PgSQL_Prod!2026_Dummy"),
    },
    "positive/tokens.py": {
        2: (
            "JWT",
            "eyJhbGciOiJIUzI1NiJ9.DUMMY_PAYLOAD_2026.SIGNATURE_FAKE",
        ),
        3: (
            "Refresh Token",
            "dGhpcy1pcy1hLWZha2UtcmVmcmVzaC10b2tlbi0yMDI2",
        ),
        4: ("Token", "AUTH_7Fh92KxP4mN8vQ3rT6yW9z"),
    },
    "positive/private_keys.py": {
        2: ("Private Key", "-----BEGIN RSA PRIVATE KEY-----"),
    },
    "positive/mixed_secrets.py": {
        2: ("API Key", "sk_live_FAKE_92KxP4mN8vQ3rT6yW"),
        3: ("Password", "FakePassword!2026"),
        4: ("Token", "FAKE_ACCESS_TOKEN_7Fh92KxP4mN8"),
        5: ("Client Secret", "CLIENT_SECRET_FAKE_2026_ABCDEF"),
    },
    "positive/demo_secrets.py": {
        5: ("API Key", "DEMO_API_KEY_123456789"),
        6: ("Password", "DemoPassword123"),
        7: ("Token", "DEMO_ACCESS_TOKEN_987654321"),
        10: ("High Entropy", "aB9xK2mP7qR4vT8nL5wZ"),
    },
}


def is_meaningful_line(line):
    """Bỏ qua dòng trống và dòng comment đơn giản."""
    stripped = line.strip()

    if not stripped:
        return False

    if stripped.startswith("#"):
        return False

    return True


def generate_ground_truth():
    records = []
    positive_count = 0
    negative_count = 0

    for category in ("positive", "negative"):
        folder = DATASET_DIR / category

        if not folder.exists():
            print(f"Không tìm thấy thư mục: {folder}")
            continue

        for file_path in sorted(folder.rglob("*")):
            if not file_path.is_file():
                continue

            relative_path = file_path.relative_to(DATASET_DIR).as_posix()

            try:
                lines = file_path.read_text(
                    encoding="utf-8"
                ).splitlines()
            except UnicodeDecodeError:
                print(f"Bỏ qua file không đọc được: {relative_path}")
                continue

            labels = POSITIVE_LABELS.get(relative_path, {})

            for line_number, line in enumerate(lines, start=1):
                if not is_meaningful_line(line):
                    continue

                if line_number in labels:
                    secret_type, expected_value = labels[line_number]

                    if expected_value not in line:
                        raise ValueError(
                            f"Nhãn không khớp nội dung tại "
                            f"{relative_path}, dòng {line_number}"
                        )

                    records.append({
                        "filename": relative_path,
                        "line": line_number,
                        "expected_type": secret_type,
                        "expected_value": expected_value,
                        "expected_secret": 1,
                    })

                    positive_count += 1

                else:
                    records.append({
                        "filename": relative_path,
                        "line": line_number,
                        "expected_type": "No Secret",
                        "expected_value": "",
                        "expected_secret": 0,
                    })

                    negative_count += 1

    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)

    with OUTPUT_FILE.open(
        "w",
        newline="",
        encoding="utf-8-sig"
    ) as csv_file:
        fieldnames = [
            "filename",
            "line",
            "expected_type",
            "expected_value",
            "expected_secret",
        ]

        writer = csv.DictWriter(
            csv_file,
            fieldnames=fieldnames
        )

        writer.writeheader()
        writer.writerows(records)

    print("Ground truth generated successfully.")
    print(f"Positive labels: {positive_count}")
    print(f"Negative labels: {negative_count}")
    print(f"Total records: {len(records)}")
    print(f"Output: {OUTPUT_FILE}")


if __name__ == "__main__":
    generate_ground_truth()