
from pathlib import Path
import argparse
import csv
import gzip
import io
import json
import tarfile
import zipfile


PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATASET_DIR = PROJECT_ROOT / "dataset"

POSITIVE_DIR = DATASET_DIR / "positive"
NEGATIVE_DIR = DATASET_DIR / "negative"

# Bộ file mẫu nhiều định dạng (--real-world), không đưa lên git.
REAL_WORLD_DIR = DATASET_DIR / "real_world"


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


# ---------------------------------------------------------------------------
# Bộ file mẫu "giống thực tế" để demo quét nhiều định dạng (--real-world).
# Mọi secret dưới đây đều là giá trị GIẢ LẬP, không dùng được ở đâu cả.
# ---------------------------------------------------------------------------

def _zip_bytes(files):
    buffer = io.BytesIO()

    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, content in files.items():
            archive.writestr(name, content)

    return buffer.getvalue()


def make_docx(text_lines):
    """Tạo file Word tối giản (chỉ đủ phần nội dung để đọc chữ)."""
    paragraphs = "".join(
        f"<w:p><w:r><w:t xml:space=\"preserve\">{line}</w:t></w:r></w:p>"
        for line in text_lines
    )
    document = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
        f"<w:body>{paragraphs}</w:body></w:document>"
    )
    return _zip_bytes({
        "[Content_Types].xml": '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"/>',
        "word/document.xml": document,
    })


def make_xlsx(cells):
    """Tạo file Excel tối giản: mỗi chuỗi là một ô trong sharedStrings."""
    items = "".join(f"<si><t>{cell}</t></si>" for cell in cells)
    shared = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
        f"{items}</sst>"
    )
    return _zip_bytes({
        "[Content_Types].xml": '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"/>',
        "xl/sharedStrings.xml": shared,
    })


def make_pdf(line):
    """Tạo PDF một trang chứa một dòng chữ (không cần thư viện ngoài)."""
    stream = f"BT /F1 12 Tf 72 720 Td ({line}) Tj ET".encode("latin-1")
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
        b"/Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>",
        b"<< /Length " + str(len(stream)).encode() + b" >>\nstream\n" + stream + b"\nendstream",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    ]
    output = io.BytesIO()
    output.write(b"%PDF-1.4\n")
    offsets = []

    for number, body in enumerate(objects, start=1):
        offsets.append(output.tell())
        output.write(f"{number} 0 obj\n".encode() + body + b"\nendobj\n")

    xref = output.tell()
    output.write(f"xref\n0 {len(objects) + 1}\n0000000000 65535 f \n".encode())

    for offset in offsets:
        output.write(f"{offset:010d} 00000 n \n".encode())

    output.write(
        f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode()
    )
    return output.getvalue()


def make_notebook(cells):
    notebook = {
        "cells": [
            {"cell_type": "code", "source": source.splitlines(keepends=True), "outputs": []}
            for source in cells
        ],
        "metadata": {},
        "nbformat": 4,
        "nbformat_minor": 5,
    }
    return json.dumps(notebook, indent=1).encode("utf-8")


def make_tar_gz(files):
    buffer = io.BytesIO()

    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        for name, content in files.items():
            data = content.encode("utf-8")
            info = tarfile.TarInfo(name)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))

    return buffer.getvalue()


def build_real_world_samples(target=None):
    target = Path(target or REAL_WORLD_DIR)
    target.mkdir(parents=True, exist_ok=True)

    files = {
        # File cấu hình không có đuôi / dotfile.
        # Key Stripe giả được ghép chuỗi để mã nguồn không chứa nguyên key
        # (GitHub Push Protection chặn chuỗi trùng định dạng Stripe);
        # file .env sinh ra vẫn có đủ key để Secret Guard phát hiện.
        ".env": "APP_ENV=production\nDB_PASSWORD=Pr0d_Db!2026\n"
                "STRIPE_SECRET_KEY=" + "sk_" + "live_51Hx9aF3kQ7mZ2xP8vL4tR6w\n",
        ".netrc": "machine api.example.com login deploy password N3trc_Pass!77\n",
        ".git-credentials": "https://deploy:Gh_Cr3d!2026@github.com\n",
        "Dockerfile": "FROM python:3.12\nENV API_TOKEN=tok_9f8e7d6c5b4a3210fedcba98\n",
        # JSON, YAML, XML, PHP, JS
        "deploy/sftp-config.json": json.dumps({"host": "example.com", "user": "root", "password": "Sftp_Pass#2026"}, indent=2),
        "deploy/docker-compose.yml": "services:\n  db:\n    environment:\n      POSTGRES_PASSWORD: Compose_Pg!2026\n",
        "deploy/settings.xml": "<settings><servers><server><id>repo</id><password>Mvn_Pass_2026!</password></server></servers></settings>\n",
        "web/wp-config.php": "<?php\ndefine('DB_PASSWORD', 'Wp_Db_Pass!2026');\ndefine('AUTH_KEY', 'k8#Lm2$Qp9@Zx4&Vb7!Nc1');\n",
        "web/app.js": "const config = { apiKey: 'AIzaSyFAKE-1234567890abcdefghijk', user: process.env.USER };\nconst password = getPassword();\n",
        # Mã băm mật khẩu
        "etc/.htpasswd": "admin:$apr1$tp8glkbm$fjg65tI1eipoBh62aEjIy0\n",
        # Khác bảng mã
        "legacy/utf16_config.ini": None,
        "legacy/cp1252_notes.txt": None,
        # Tài liệu
        "docs/ban_giao.docx": make_docx(["Bàn giao hệ thống", "Mật khẩu quản trị:", "admin_password = Docx_Adm1n!2026"]),
        "docs/tai_khoan.xlsx": make_xlsx(["service", "db_password=Xlsx_Db!2026"]),
        "docs/huong_dan.pdf": make_pdf('SMTP_PASSWORD = "Pdf_Smtp!2026"'),
        "notebooks/phan_tich.ipynb": make_notebook([
            "import openai\nopenai.api_key = \"sk-proj-FAKE9aF3kQ7mZ2xP8vL4tR6wYz\"\n",
            "df = load('data.csv')\n",
        ]),
        # File nén
        "backup/config_backup.zip": _zip_bytes({"config/.env": "AWS_SECRET_ACCESS_KEY=FAKEwJalrXUtnFEMI/K7MDENG/bPxRfiCY2026\n"}),
        "backup/site.tar.gz": make_tar_gz({"site/config.json": json.dumps({"db": {"password": "Tar_Db_Pass!2026"}})}),
        "backup/secrets.env.gz": gzip.compress(b"REDIS_PASSWORD=Gz_Redis!2026\n"),
        # Không chứa secret / phải bị bỏ qua
        "src/clean.py": "import os\npassword = os.getenv('DB_PASSWORD')\nAPI_URL = 'https://api.example.com/v1'\n",
        "assets/logo.png": b"\x89PNG\r\n\x1a\n" + bytes(range(256)) * 4,
        "data/model.bin": b"\x00\x01\x02\x03" * 512,
        "package-lock.json": json.dumps({"integrity": "sha512-" + "A" * 86}),
    }

    for relative, content in files.items():
        path = target / relative
        path.parent.mkdir(parents=True, exist_ok=True)

        if relative == "legacy/utf16_config.ini":
            path.write_bytes("[database]\npassword = Utf16_Pass!2026\n".encode("utf-16"))
        elif relative == "legacy/cp1252_notes.txt":
            path.write_bytes("Ghi chú café\nftp_password=Cp1252_Ftp!2026\n".encode("cp1252", errors="replace"))
        elif isinstance(content, bytes):
            path.write_bytes(content)
        else:
            path.write_text(content, encoding="utf-8")

    return target


def main():
    parser = argparse.ArgumentParser(description="Tạo bộ dữ liệu cho Secret Guard.")
    parser.add_argument(
        "--real-world",
        nargs="?",
        const=str(REAL_WORLD_DIR),
        metavar="THU_MUC",
        help="Tạo bộ file mẫu nhiều định dạng (Word, Excel, PDF, zip...) "
             "thay vì bộ positive/negative. Mặc định: dataset/real_world",
    )
    args = parser.parse_args()

    if args.real_world:
        output = build_real_world_samples(Path(args.real_world))
        print(f"Đã tạo file mẫu tại: {output.resolve()}")
        return

    write_dataset_files()
    generate_ground_truth()

    print("\nDataset generation completed.")
    print(f"Positive files: {len(POSITIVE_DATA)}")
    print(f"Negative files: {len(NEGATIVE_DATA)}")


if __name__ == "__main__":
    main()
