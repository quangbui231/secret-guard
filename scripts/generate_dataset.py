
from pathlib import Path
import csv


PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATASET_DIR = PROJECT_ROOT / "dataset"

POSITIVE_DIR = DATASET_DIR / "positive"
NEGATIVE_DIR = DATASET_DIR / "negative"


POSITIVE_DATA = {
    "api_keys.py": '''# API keys giả lập theo định dạng thường gặp
api_key = "sk_test_7Fh92KxP4mN8vQ3rT6yW"
service_api_key = "AIzaSyDUMMY7Fh92KxP4mN8vQ3"
aws_api_key = "AKIAIOSFODNN7EXAMPLE"
''',

    "database_credentials.py": '''# Database credentials giả lập
database_password = "PgSQL_Prod!2026_Dummy"
db_password = "M0ngoDB!Secure_Example"
password = "RedisPass#2026_Test"

# Connection string giả lập
database_url = "postgresql://app_user:PgSQL_Prod!2026_Dummy@localhost:5432/app_db"
''',

    "tokens.py": '''# Token giả lập, không có quyền truy cập hệ thống thật
access_token = "eyJhbGciOiJIUzI1NiJ9.DUMMY_PAYLOAD_2026.SIGNATURE_FAKE"
refresh_token = "dGhpcy1pcy1hLWZha2UtcmVmcmVzaC10b2tlbi0yMDI2"
auth_token = "AUTH_7Fh92KxP4mN8vQ3rT6yW9z"
''',

    "private_keys.py": '''# Cấu trúc PEM giả lập, không phải khóa mật mã hợp lệ
private_key = """-----BEGIN RSA PRIVATE KEY-----
FAKE_PRIVATE_KEY_DATA_FOR_SECRET_GUARD_TESTING
-----END RSA PRIVATE KEY-----
'''
,

    "mixed_secrets.py": '''# Nhiều loại secret giả lập trong cùng file
api_key = "sk_live_FAKE_92KxP4mN8vQ3rT6yW"
password = "FakePassword!2026"
access_token = "FAKE_ACCESS_TOKEN_7Fh92KxP4mN8"
client_secret = "CLIENT_SECRET_FAKE_2026_ABCDEF"
'''
}


NEGATIVE_DATA = {
    "normal_code.py": '''# Mã nguồn bình thường
def calculate_total(price, quantity):
    return price * quantity

def greet_user(name):
    return f"Hello, {name}"
''',

    "placeholders.py": '''# Các placeholder không phải secret thật
password = "YOUR_PASSWORD_HERE"
api_key = "YOUR_API_KEY_HERE"
secret = "your_secret_here"
token = "placeholder"
''',

    "environment_variables.py": '''# Tham chiếu biến môi trường, không chứa giá trị secret
database_password = "${DATABASE_PASSWORD}"
api_key = "${API_KEY}"
access_token = "$ACCESS_TOKEN"
''',

    "normal_config.yaml": '''# Cấu hình ứng dụng thông thường
application:
  name: secret-guard-demo
  environment: development
  debug: true

database:
  host: localhost
  port: 5432
  username: app_user
''',

    "normal_data.py": '''# Dữ liệu thông thường không chứa secret
user_id = 123456
order_id = 987654
product_code = "PRODUCT_2026"
status = "active"

# Chuỗi lặp, entropy thấp
sample_code = "AAAAAAAAAAAAAAAAAAAA"
'''
}


def write_dataset_files():
    POSITIVE_DIR.mkdir(parents=True, exist_ok=True)
    NEGATIVE_DIR.mkdir(parents=True, exist_ok=True)

    for filename, content in POSITIVE_DATA.items():
        (POSITIVE_DIR / filename).write_text(
            content,
            encoding="utf-8",
        )

    for filename, content in NEGATIVE_DATA.items():
        (NEGATIVE_DIR / filename).write_text(
            content,
            encoding="utf-8",
        )

    print("Dataset files created successfully.")


def generate_ground_truth():
    records = []

    # Các loại secret được biết trước trong tập positive.
    secret_types = {
        "api_keys.py": "API Key",
        "database_credentials.py": "Database Password",
        "tokens.py": "Token",
        "private_keys.py": "Private Key",
        "mixed_secrets.py": "Multiple Secrets",
    }

    for filename, expected_type in secret_types.items():
        filepath = POSITIVE_DIR / filename
        content = filepath.read_text(encoding="utf-8")

        for line_number, line in enumerate(
            content.splitlines(),
            start=1,
        ):
            if "=" in line and not line.lstrip().startswith("#"):
                records.append({
                    "filename": f"positive/{filename}",
                    "line": line_number,
                    "expected_type": expected_type,
                    "expected_secret": 1,
                })

    for filename in NEGATIVE_DATA:
        filepath = NEGATIVE_DIR / filename
        content = filepath.read_text(encoding="utf-8")

        for line_number, line in enumerate(
            content.splitlines(),
            start=1,
        ):
            if "=" in line and not line.lstrip().startswith("#"):
                records.append({
                    "filename": f"negative/{filename}",
                    "line": line_number,
                    "expected_type": "Normal or placeholder",
                    "expected_secret": 0,
                })

    output_path = DATASET_DIR / "ground_truth.csv"

    with output_path.open(
        "w",
        newline="",
        encoding="utf-8-sig",
    ) as csvfile:
        fieldnames = [
            "filename",
            "line",
            "expected_type",
            "expected_secret",
        ]

        writer = csv.DictWriter(
            csvfile,
            fieldnames=fieldnames,
        )

        writer.writeheader()
        writer.writerows(records)

    print(f"Ground truth created: {output_path}")
    print(f"Total labeled lines: {len(records)}")


def main():
    write_dataset_files()
    generate_ground_truth()

    print("\nDataset generation completed.")
    print(f"Positive files: {len(POSITIVE_DATA)}")
    print(f"Negative files: {len(NEGATIVE_DATA)}")


if __name__ == "__main__":
    main()
