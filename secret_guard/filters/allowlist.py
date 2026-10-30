
import re
from pathlib import Path, PurePosixPath, PureWindowsPath


class Allowlist:
    """
    Quản lý các phát hiện được phép bỏ qua.

    Hỗ trợ:
    - Allowlist theo giá trị secret chính xác.
    - Allowlist theo đường dẫn file và số dòng.
    - Đọc cấu hình từ YAML.
    - Cho phép bổ sung quy tắc khi khởi tạo.
    """

    def __init__(
        self,
        allowed_secrets=None,
        allowed_locations=None,
        config_path=None,
    ):
        self.allowed_secrets = set()
        self.allowed_locations = []
        self.config_path = config_path

        for secret in allowed_secrets or []:
            if not isinstance(secret, str):
                raise TypeError(
                    "Mỗi giá trị allowlist phải là chuỗi."
                )
            self.allowed_secrets.add(secret)

        for location in allowed_locations or []:
            self._add_location(location)

        if config_path is not None:
            self.load_config(config_path)

    @staticmethod
    def _normalize_path(path):
        """
        Chuẩn hóa dấu phân cách đường dẫn cho Windows và Linux.
        """
        if not isinstance(path, str) or not path.strip():
            raise ValueError("Đường dẫn file không được để trống.")

        path = path.strip().replace("\\", "/")

        windows_path = PureWindowsPath(path)
        if windows_path.drive:
            return str(windows_path).replace("\\", "/").lower()

        return str(PurePosixPath(path))

    def _add_location(self, location):
        if not isinstance(location, dict):
            raise TypeError(
                "Mỗi allowlist location phải là dictionary."
            )

        filename = location.get("filename")
        line = location.get("line")

        normalized_filename = self._normalize_path(filename)

        if not isinstance(line, int) or isinstance(line, bool):
            raise TypeError("line phải là số nguyên.")

        if line < 1:
            raise ValueError("line phải lớn hơn hoặc bằng 1.")

        self.allowed_locations.append({
            "filename": normalized_filename,
            "line": line,
        })

    def load_config(self, config_path):
        """
        Đọc cấu hình YAML có dạng:

        allowed_secrets:
          - EXAMPLE_SECRET_VALUE

        allowed_locations:
          - filename: tests/fixtures/example.py
            line: 10
        """
        path = Path(config_path)

        if not path.is_file():
            raise FileNotFoundError(
                f"Không tìm thấy file allowlist: {path}"
            )

        try:
            import yaml
        except ImportError as error:
            raise RuntimeError(
                "Cần cài PyYAML để đọc cấu hình YAML. "
                "Chạy: python -m pip install PyYAML"
            ) from error

        try:
            with path.open("r", encoding="utf-8") as file:
                config = yaml.safe_load(file)
        except yaml.YAMLError as error:
            raise ValueError(
                f"File YAML không hợp lệ: {path}"
            ) from error

        if config is None:
            config = {}

        if not isinstance(config, dict):
            raise ValueError(
                "Cấu hình allowlist phải là một dictionary YAML."
            )

        unknown_keys = set(config) - {
            "allowed_secrets",
            "allowed_locations",
        }

        if unknown_keys:
            raise ValueError(
                "Khóa cấu hình không được hỗ trợ: "
                + ", ".join(sorted(unknown_keys))
            )

        secrets = config.get("allowed_secrets", [])
        locations = config.get("allowed_locations", [])

        if not isinstance(secrets, list):
            raise TypeError("allowed_secrets phải là một list.")

        if not isinstance(locations, list):
            raise TypeError("allowed_locations phải là một list.")

        for secret in secrets:
            if not isinstance(secret, str):
                raise TypeError(
                    "Mỗi giá trị allowed_secrets phải là chuỗi."
                )
            self.allowed_secrets.add(secret)

        for location in locations:
            self._add_location(location)

    def is_allowlisted(self, finding):
        """
        Trả về True nếu phát hiện thuộc allowlist,
        ngược lại trả về False.
        """
        if not isinstance(finding, dict):
            raise TypeError("finding phải là một dictionary.")

        secret = finding.get("secret")

        # Chỉ so khớp chính xác, không dùng chuỗi con.
        if isinstance(secret, str):
            if secret in self.allowed_secrets:
                return True

        filename = finding.get("filename")
        line = finding.get("line")

        # Thiếu thông tin vị trí thì không áp dụng
        # allowlist theo file và dòng.
        if not isinstance(filename, str):
            return False

        if not isinstance(line, int) or isinstance(line, bool):
            return False

        try:
            normalized_filename = self._normalize_path(filename)
        except ValueError:
            return False

        for location in self.allowed_locations:
            if (
                normalized_filename == location["filename"]
                and line == location["line"]
            ):
                return True

        return False

    def filter_findings(self, findings):
        """
        Trả về các phát hiện không nằm trong allowlist.
        Không sửa danh sách đầu vào.
        """
        if not isinstance(findings, list):
            raise TypeError("findings phải là một list.")

        results = []

        for finding in findings:
            if not isinstance(finding, dict):
                raise TypeError(
                    "Mỗi phát hiện phải là một dictionary."
                )

            if not self.is_allowlisted(finding):
                results.append(finding.copy())

        return results
