"""
Đọc nội dung văn bản từ các loại file gặp trong thực tế.

Module này tách phần "đọc file" khỏi phần "phát hiện secret":
- Nhận diện file nhị phân để bỏ qua (ảnh, file thực thi, cơ sở dữ liệu...).
- Tự nhận diện bảng mã: UTF-8, UTF-8 có BOM, UTF-16/32 có BOM,
  rồi lùi về cp1252/latin-1 cho file cũ trên Windows.
- Giới hạn kích thước file để không treo khi gặp file rất lớn.
- Trích văn bản từ tài liệu Office (docx, xlsx, pptx, odt, ods, odp),
  PDF (nếu đã cài pypdf) và Jupyter notebook (.ipynb).
- Mở file nén (zip, jar, tar, tar.gz, tgz, tar.bz2, tar.xz, gz) và quét
  từng file bên trong, có giới hạn chống "zip bomb".

Kết quả đọc là danh sách TextSource. File bên trong file nén được đặt
tên theo dạng "duong/dan/file.zip!thu_muc/ben_trong.py".
"""

import bz2
import gzip
import io
import json
import lzma
import re
import tarfile
import zipfile
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from xml.etree import ElementTree


MB = 1024 * 1024

ARCHIVE_SEPARATOR = "!"


@dataclass
class TextSource:
    """Một đơn vị văn bản cần quét."""

    name: str
    text: str
    kind: str = "text"
    encoding: str = "utf-8"


@dataclass
class SkippedItem:
    """Một file hoặc thành phần bị bỏ qua và lý do."""

    name: str
    reason: str


@dataclass
class ReadResult:
    sources: list = field(default_factory=list)
    skipped: list = field(default_factory=list)


class FileReader:
    """
    Đọc file bất kỳ và trả về các đoạn văn bản có thể quét.
    """

    # Đuôi file chắc chắn là nhị phân: bỏ qua ngay, không cần đọc.
    BINARY_EXTENSIONS = {
        # Ảnh
        ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".webp", ".tif",
        ".tiff", ".psd", ".heic", ".avif",
        # Âm thanh, video
        ".mp3", ".wav", ".flac", ".ogg", ".m4a", ".aac", ".mp4", ".mkv",
        ".avi", ".mov", ".wmv", ".webm",
        # Font
        ".ttf", ".otf", ".woff", ".woff2", ".eot",
        # File thực thi, thư viện, mã đã biên dịch
        ".exe", ".dll", ".so", ".dylib", ".bin", ".o", ".a", ".lib",
        ".class", ".pyc", ".pyo", ".pyd", ".wasm",
        # Dữ liệu nhị phân, mô hình
        ".db", ".sqlite", ".sqlite3", ".parquet", ".avro", ".orc",
        ".pkl", ".pickle", ".npy", ".npz", ".h5", ".hdf5", ".pt", ".pth",
        ".onnx", ".safetensors", ".ckpt",
        # Định dạng nén không hỗ trợ đọc bên trong
        ".7z", ".rar", ".iso", ".dmg",
        # Tài liệu cũ dạng nhị phân
        ".doc", ".xls", ".ppt",
    }

    OFFICE_XML_PARTS = {
        ".docx": ("word/",),
        ".xlsx": ("xl/sharedStrings.xml", "xl/worksheets/"),
        ".pptx": ("ppt/slides/",),
        ".odt": ("content.xml",),
        ".ods": ("content.xml",),
        ".odp": ("content.xml",),
    }

    ZIP_ARCHIVES = {".zip", ".jar", ".war", ".ear", ".apk", ".whl", ".nupkg"}
    TAR_SUFFIXES = (".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tbz2", ".tar.xz", ".txz")

    # Chặn zip bomb: tỷ lệ nén quá cao là dấu hiệu bất thường.
    MAX_COMPRESSION_RATIO = 100

    CONTROL_CHARACTERS = set(range(0, 32)) - {9, 10, 12, 13, 8, 27}

    def __init__(
        self,
        max_file_size=10 * MB,
        scan_archives=True,
        scan_documents=True,
        max_archive_depth=2,
        max_archive_members=5000,
        max_archive_total=200 * MB,
    ):
        if max_file_size <= 0:
            raise ValueError("max_file_size phải lớn hơn 0.")

        self.max_file_size = max_file_size
        self.scan_archives = scan_archives
        self.scan_documents = scan_documents
        self.max_archive_depth = max_archive_depth
        self.max_archive_members = max_archive_members
        self.max_archive_total = max_archive_total

    # ------------------------------------------------------------------
    # Nhận diện loại file và bảng mã
    # ------------------------------------------------------------------

    @staticmethod
    def _suffix(name):
        # Chỉ xét tên file cuối cùng (kể cả trong file nén, kể cả đường dẫn Windows).
        lowered = name.replace("\\", "/").split(ARCHIVE_SEPARATOR)[-1].split("/")[-1].lower()

        for suffix in FileReader.TAR_SUFFIXES:
            if lowered.endswith(suffix):
                return suffix

        return PurePosixPath(lowered).suffix

    def looks_binary(self, data):
        """
        Đoán dữ liệu có phải nhị phân không dựa trên 8 KB đầu.
        """
        sample = data[:8192]

        if not sample:
            return False

        if sample.startswith((b"\xff\xfe", b"\xfe\xff", b"\xef\xbb\xbf")):
            return False

        if b"\x00" in sample:
            return not self._looks_like_utf16_without_bom(sample)

        control = sum(1 for byte in sample if byte in self.CONTROL_CHARACTERS)

        return control / len(sample) > 0.10

    @staticmethod
    def _looks_like_utf16_without_bom(sample):
        """
        File UTF-16 không có BOM có byte 0 xen kẽ đều đặn (văn bản ASCII).
        """
        if len(sample) < 4:
            return False

        even_zero = sample[0::2].count(0) / max(len(sample[0::2]), 1)
        odd_zero = sample[1::2].count(0) / max(len(sample[1::2]), 1)

        return (even_zero > 0.4 and odd_zero < 0.05) or (
            odd_zero > 0.4 and even_zero < 0.05
        )

    def decode(self, data):
        """
        Giải mã bytes thành chuỗi.

        Trả về (text, encoding) hoặc (None, lý do) nếu là nhị phân.
        """
        if data.startswith(b"\xef\xbb\xbf"):
            return data[3:].decode("utf-8", errors="replace"), "utf-8-sig"

        if data.startswith((b"\xff\xfe\x00\x00", b"\x00\x00\xfe\xff")):
            return data.decode("utf-32", errors="replace"), "utf-32"

        if data.startswith((b"\xff\xfe", b"\xfe\xff")):
            return data.decode("utf-16", errors="replace"), "utf-16"

        sample = data[:8192]

        if b"\x00" in sample and self._looks_like_utf16_without_bom(sample):
            even_zero = sample[0::2].count(0) > sample[1::2].count(0)
            encoding = "utf-16-be" if even_zero else "utf-16-le"
            return data.decode(encoding, errors="replace"), encoding

        if self.looks_binary(data):
            return None, "file nhị phân"

        try:
            return data.decode("utf-8"), "utf-8"
        except UnicodeDecodeError:
            pass

        for encoding in ("cp1252", "latin-1"):
            try:
                return data.decode(encoding), encoding
            except UnicodeDecodeError:
                continue

        return None, "không giải mã được"

    # ------------------------------------------------------------------
    # Trích văn bản từ tài liệu
    # ------------------------------------------------------------------

    @staticmethod
    def _xml_to_text(xml_bytes):
        """
        Lấy toàn bộ chữ trong một file XML, mỗi đoạn một dòng.
        """
        try:
            root = ElementTree.fromstring(xml_bytes)
        except ElementTree.ParseError:
            text = xml_bytes.decode("utf-8", errors="replace")
            return re.sub(r"<[^>]+>", " ", text)

        lines = []
        paragraph = []

        paragraph_tags = ("}p", "}tr", "}si", "}row", "}h", "}list-item")

        for element in root.iter():
            if element.text and element.text.strip():
                paragraph.append(element.text)

            if element.tag.endswith(paragraph_tags) and paragraph:
                lines.append("".join(paragraph))
                paragraph = []

            if element.tail and element.tail.strip():
                paragraph.append(element.tail)

        if paragraph:
            lines.append("".join(paragraph))

        return "\n".join(lines)

    def _extract_office(self, data, name, suffix):
        parts = self.OFFICE_XML_PARTS[suffix]

        try:
            archive = zipfile.ZipFile(io.BytesIO(data))
        except zipfile.BadZipFile:
            return None, "tài liệu Office bị hỏng"

        texts = []

        with archive:
            for info in sorted(archive.infolist(), key=lambda item: item.filename):
                if not info.filename.endswith(".xml"):
                    continue

                if not any(
                    info.filename == part or info.filename.startswith(part)
                    for part in parts
                ):
                    continue

                if self._is_suspicious_member(info.file_size, info.compress_size):
                    return None, "tỷ lệ nén bất thường"

                texts.append(f"# --- {info.filename} ---")
                texts.append(self._xml_to_text(archive.read(info)))

        return "\n".join(texts), "office"

    @staticmethod
    def _extract_pdf(data):
        try:
            from pypdf import PdfReader
        except ImportError:
            return None, "cần cài pypdf để đọc PDF"

        try:
            reader = PdfReader(io.BytesIO(data))

            if reader.is_encrypted:
                return None, "PDF có mật khẩu"

            pages = []

            for number, page in enumerate(reader.pages, start=1):
                pages.append(f"# --- trang {number} ---")
                pages.append(page.extract_text() or "")

            return "\n".join(pages), "pdf"

        except Exception as error:  # pypdf ném nhiều loại lỗi khác nhau
            return None, f"không đọc được PDF ({type(error).__name__})"

    def _extract_notebook(self, data):
        """
        Lấy mã và kết quả in ra của từng ô trong Jupyter notebook.
        """
        text, encoding = self.decode(data)

        if text is None:
            return None, encoding

        try:
            notebook = json.loads(text)
        except json.JSONDecodeError:
            return text, encoding

        lines = []

        for index, cell in enumerate(notebook.get("cells", []), start=1):
            lines.append(f"# --- cell {index} ({cell.get('cell_type', '?')}) ---")
            source = cell.get("source", "")
            lines.append("".join(source) if isinstance(source, list) else str(source))

            for output in cell.get("outputs", []) or []:
                value = output.get("text")

                if value is None:
                    value = (output.get("data") or {}).get("text/plain")

                if value:
                    lines.append("".join(value) if isinstance(value, list) else str(value))

        return "\n".join(lines), "notebook"

    # ------------------------------------------------------------------
    # File nén
    # ------------------------------------------------------------------

    def _is_suspicious_member(self, file_size, compress_size):
        if file_size > self.max_file_size:
            return True

        if compress_size and file_size / compress_size > self.MAX_COMPRESSION_RATIO:
            return True

        return False

    def _read_zip(self, data, name, depth, result):
        try:
            archive = zipfile.ZipFile(io.BytesIO(data))
        except zipfile.BadZipFile:
            result.skipped.append(SkippedItem(name, "file zip bị hỏng"))
            return

        total = 0

        with archive:
            members = [info for info in archive.infolist() if not info.is_dir()]

            if len(members) > self.max_archive_members:
                result.skipped.append(SkippedItem(name, "file nén có quá nhiều thành phần"))
                return

            for info in members:
                member_name = f"{name}{ARCHIVE_SEPARATOR}{info.filename}"

                if info.flag_bits & 0x1:
                    result.skipped.append(SkippedItem(member_name, "thành phần được mã hóa"))
                    continue

                if self._is_suspicious_member(info.file_size, info.compress_size):
                    result.skipped.append(SkippedItem(member_name, "quá lớn hoặc tỷ lệ nén bất thường"))
                    continue

                total += info.file_size

                if total > self.max_archive_total:
                    result.skipped.append(SkippedItem(name, "tổng dung lượng giải nén vượt giới hạn"))
                    return

                self._read_bytes(archive.read(info), member_name, depth + 1, result)

    def _read_tar(self, data, name, depth, result):
        try:
            archive = tarfile.open(fileobj=io.BytesIO(data), mode="r:*")
        except (tarfile.TarError, EOFError, OSError, lzma.LZMAError):
            result.skipped.append(SkippedItem(name, "file tar bị hỏng"))
            return

        total = 0
        count = 0

        with archive:
            for member in archive:
                if not member.isfile():
                    continue

                count += 1
                member_name = f"{name}{ARCHIVE_SEPARATOR}{member.name}"

                if count > self.max_archive_members:
                    result.skipped.append(SkippedItem(name, "file nén có quá nhiều thành phần"))
                    return

                if member.size > self.max_file_size:
                    result.skipped.append(SkippedItem(member_name, "quá lớn"))
                    continue

                total += member.size

                if total > self.max_archive_total:
                    result.skipped.append(SkippedItem(name, "tổng dung lượng giải nén vượt giới hạn"))
                    return

                extracted = archive.extractfile(member)

                if extracted is None:
                    continue

                self._read_bytes(extracted.read(), member_name, depth + 1, result)

    def _read_single_compressed(self, data, name, suffix, depth, result):
        """Giải nén file .gz/.bz2/.xz chứa một file duy nhất."""
        opener = {".gz": gzip.open, ".bz2": bz2.open, ".xz": lzma.open}[suffix]

        try:
            with opener(io.BytesIO(data)) as handle:
                content = handle.read(self.max_file_size + 1)
        except (OSError, EOFError, lzma.LZMAError):
            result.skipped.append(SkippedItem(name, "file nén bị hỏng"))
            return

        if len(content) > self.max_file_size:
            result.skipped.append(SkippedItem(name, "nội dung giải nén quá lớn"))
            return

        last_part = name.replace("\\", "/").split(ARCHIVE_SEPARATOR)[-1]
        inner_name = f"{name}{ARCHIVE_SEPARATOR}{PurePosixPath(last_part).stem}"
        self._read_bytes(content, inner_name, depth + 1, result)

    # ------------------------------------------------------------------
    # Điểm vào chung
    # ------------------------------------------------------------------

    def _read_bytes(self, data, name, depth, result):
        suffix = self._suffix(name)

        if suffix in self.BINARY_EXTENSIONS:
            result.skipped.append(SkippedItem(name, f"định dạng nhị phân ({suffix})"))
            return

        is_archive = (
            suffix in self.ZIP_ARCHIVES
            or suffix in self.TAR_SUFFIXES
            or suffix in {".gz", ".bz2", ".xz"}
        )

        if is_archive:
            if not self.scan_archives:
                result.skipped.append(SkippedItem(name, "bỏ qua file nén (--no-archives)"))
                return

            if depth >= self.max_archive_depth:
                result.skipped.append(SkippedItem(name, "file nén lồng quá sâu"))
                return

            if suffix in self.ZIP_ARCHIVES:
                self._read_zip(data, name, depth, result)
            elif suffix in self.TAR_SUFFIXES:
                self._read_tar(data, name, depth, result)
            else:
                self._read_single_compressed(data, name, suffix, depth, result)
            return

        if suffix in self.OFFICE_XML_PARTS or suffix == ".pdf":
            if not self.scan_documents:
                result.skipped.append(SkippedItem(name, "bỏ qua tài liệu (--no-documents)"))
                return

            if suffix == ".pdf":
                text, info = self._extract_pdf(data)
            else:
                text, info = self._extract_office(data, name, suffix)

            if text is None:
                result.skipped.append(SkippedItem(name, info))
            else:
                result.sources.append(TextSource(name, text, kind="document", encoding=info))
            return

        if suffix == ".ipynb":
            text, info = self._extract_notebook(data)

            if text is None:
                result.skipped.append(SkippedItem(name, info))
            else:
                result.sources.append(TextSource(name, text, kind="notebook", encoding=info))
            return

        text, info = self.decode(data)

        if text is None:
            result.skipped.append(SkippedItem(name, info))
            return

        result.sources.append(TextSource(name, text, kind="text", encoding=info))

    def read(self, path):
        """
        Đọc một file trên đĩa.

        Returns:
            ReadResult: các đoạn văn bản cần quét và các mục bị bỏ qua.
        """
        path = Path(path)
        result = ReadResult()
        name = str(path)

        if not path.is_file():
            raise FileNotFoundError(f"Không tìm thấy file: {path}")

        suffix = self._suffix(name)

        if suffix in self.BINARY_EXTENSIONS:
            result.skipped.append(SkippedItem(name, f"định dạng nhị phân ({suffix})"))
            return result

        size = path.stat().st_size
        is_container = (
            suffix in self.ZIP_ARCHIVES
            or suffix in self.TAR_SUFFIXES
            or suffix in {".gz", ".bz2", ".xz"}
        )
        limit = self.max_archive_total if is_container else self.max_file_size

        if size > limit:
            result.skipped.append(
                SkippedItem(name, f"quá lớn ({size / MB:.1f} MB > {limit / MB:.0f} MB)")
            )
            return result

        try:
            data = path.read_bytes()
        except OSError as error:
            result.skipped.append(SkippedItem(name, f"không đọc được ({error.strerror or error})"))
            return result

        self._read_bytes(data, name, 0, result)
        return result
