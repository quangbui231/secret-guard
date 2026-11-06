import gzip
import importlib.util
import io
import json
import tarfile
import zipfile
from pathlib import Path

import pytest

from secret_guard.filters.file_filter import FileReader, MB


ROOT = Path(__file__).resolve().parent.parent


def load_sample_builder():
    path = ROOT / "scripts" / "generate_dataset.py"
    spec = importlib.util.spec_from_file_location("generate_dataset", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def read_one(path, **kwargs):
    result = FileReader(**kwargs).read(path)
    return result


def test_plain_utf8(tmp_path):
    file = tmp_path / "a.txt"
    file.write_text("password = 'Abc12345!'", encoding="utf-8")

    result = read_one(file)

    assert len(result.sources) == 1
    assert result.sources[0].encoding == "utf-8"
    assert "Abc12345!" in result.sources[0].text


def test_utf8_with_bom(tmp_path):
    file = tmp_path / "bom.ini"
    file.write_bytes(b"\xef\xbb\xbfpassword=Bom_Pass!1")

    result = read_one(file)

    assert result.sources[0].encoding == "utf-8-sig"
    assert result.sources[0].text.startswith("password")


def test_utf16_with_bom(tmp_path):
    file = tmp_path / "u16.ini"
    file.write_bytes("password = Utf16_Pass!1\n".encode("utf-16"))

    result = read_one(file)

    assert result.sources[0].encoding == "utf-16"
    assert "Utf16_Pass!1" in result.sources[0].text


def test_utf16_without_bom(tmp_path):
    file = tmp_path / "u16le.txt"
    file.write_bytes("password = NoBom_Pass!1\n".encode("utf-16-le"))

    result = read_one(file)

    assert result.sources[0].encoding == "utf-16-le"
    assert "NoBom_Pass!1" in result.sources[0].text


def test_cp1252_fallback(tmp_path):
    file = tmp_path / "old.txt"
    file.write_bytes("café\nftp_password=Old_Ftp!1\n".encode("cp1252"))

    result = read_one(file)

    assert result.sources[0].encoding == "cp1252"
    assert "café" in result.sources[0].text


def test_binary_extension_is_skipped(tmp_path):
    file = tmp_path / "logo.png"
    file.write_bytes(b"\x89PNG\r\n\x1a\n" + bytes(100))

    result = read_one(file)

    assert result.sources == []
    assert "nhị phân" in result.skipped[0].reason


def test_binary_content_is_skipped(tmp_path):
    file = tmp_path / "blob"
    file.write_bytes(bytes(range(256)) * 10)

    result = read_one(file)

    assert result.sources == []
    assert result.skipped[0].reason == "file nhị phân"


def test_file_size_limit(tmp_path):
    file = tmp_path / "big.log"
    file.write_text("x" * (2 * MB), encoding="utf-8")

    result = read_one(file, max_file_size=1 * MB)

    assert result.sources == []
    assert result.skipped[0].reason.startswith("quá lớn")


def test_missing_file_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        FileReader().read(tmp_path / "missing.txt")


def test_docx_and_xlsx_text_is_extracted(tmp_path):
    samples = load_sample_builder()
    docx = tmp_path / "a.docx"
    xlsx = tmp_path / "b.xlsx"
    docx.write_bytes(samples.make_docx(["admin_password = Docx_Pass!1"]))
    xlsx.write_bytes(samples.make_xlsx(["db_password=Xlsx_Pass!1"]))

    assert "Docx_Pass!1" in read_one(docx).sources[0].text
    assert "Xlsx_Pass!1" in read_one(xlsx).sources[0].text


def test_pdf_text_is_extracted(tmp_path):
    pytest.importorskip("pypdf")
    samples = load_sample_builder()
    pdf = tmp_path / "c.pdf"
    pdf.write_bytes(samples.make_pdf('SMTP_PASSWORD = "Pdf_Pass!1"'))

    result = read_one(pdf)

    assert result.sources[0].kind == "document"
    assert "Pdf_Pass!1" in result.sources[0].text


def test_documents_can_be_disabled(tmp_path):
    samples = load_sample_builder()
    docx = tmp_path / "a.docx"
    docx.write_bytes(samples.make_docx(["secret"]))

    result = read_one(docx, scan_documents=False)

    assert result.sources == []
    assert "--no-documents" in result.skipped[0].reason


def test_notebook_cells_are_extracted(tmp_path):
    notebook = {
        "cells": [
            {"cell_type": "code", "source": ["api_key = \"nb_Key_123456\"\n"], "outputs": [
                {"output_type": "stream", "text": ["token printed: tok_ABC\n"]},
            ]},
        ],
    }
    file = tmp_path / "n.ipynb"
    file.write_text(json.dumps(notebook), encoding="utf-8")

    text = read_one(file).sources[0].text

    assert 'api_key = "nb_Key_123456"' in text
    assert "tok_ABC" in text


def test_zip_members_are_named_with_separator(tmp_path):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("config/.env", "DB_PASSWORD=Zip_Pass!1\n")
    file = tmp_path / "backup.zip"
    file.write_bytes(buffer.getvalue())

    result = read_one(file)

    assert result.sources[0].name.endswith("backup.zip!config/.env")
    assert "Zip_Pass!1" in result.sources[0].text


def test_nested_archives_stop_at_depth_limit(tmp_path):
    inner = io.BytesIO()
    with zipfile.ZipFile(inner, "w") as archive:
        archive.writestr("deep.txt", "password=Deep_Pass!1")
    outer = io.BytesIO()
    with zipfile.ZipFile(outer, "w") as archive:
        archive.writestr("inner.zip", inner.getvalue())
    file = tmp_path / "outer.zip"
    file.write_bytes(outer.getvalue())

    allowed = read_one(file, max_archive_depth=2)
    blocked = read_one(file, max_archive_depth=1)

    assert any("Deep_Pass!1" in source.text for source in allowed.sources)
    assert blocked.sources == []
    assert "lồng quá sâu" in blocked.skipped[0].reason


def test_zip_bomb_member_is_rejected(tmp_path):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("bomb.txt", "0" * (5 * MB))
    file = tmp_path / "bomb.zip"
    file.write_bytes(buffer.getvalue())

    result = read_one(file)

    assert result.sources == []
    assert "tỷ lệ nén" in result.skipped[0].reason


def test_tar_gz_and_gz(tmp_path):
    data = b'{"password": "Tar_Pass!1"}'
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        info = tarfile.TarInfo("site/config.json")
        info.size = len(data)
        archive.addfile(info, io.BytesIO(data))
    tar_file = tmp_path / "site.tar.gz"
    tar_file.write_bytes(buffer.getvalue())

    gz_file = tmp_path / "secrets.env.gz"
    gz_file.write_bytes(gzip.compress(b"REDIS_PASSWORD=Gz_Pass!1\n"))

    tar_result = read_one(tar_file)
    gz_result = read_one(gz_file)

    assert tar_result.sources[0].name.endswith("site.tar.gz!site/config.json")
    assert gz_result.sources[0].name.endswith("secrets.env.gz!secrets.env")
    assert "Gz_Pass!1" in gz_result.sources[0].text


def test_archives_can_be_disabled(tmp_path):
    file = tmp_path / "a.zip"
    file.write_bytes(b"PK\x05\x06" + bytes(18))

    result = read_one(file, scan_archives=False)

    assert "--no-archives" in result.skipped[0].reason


@pytest.mark.parametrize(
    "name, expected",
    [
        ("C:\\proj.v2\\backup.zip", ".zip"),
        ("C:\\data\\site.tar.gz", ".tar.gz"),
        ("/home/u/a.b/notes.docx", ".docx"),
        ("backup.zip!config/app.json", ".json"),
        ("Dockerfile", ""),
    ],
)
def test_suffix_handles_windows_paths_and_archive_members(name, expected):
    assert FileReader._suffix(name) == expected
