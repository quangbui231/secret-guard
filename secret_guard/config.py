
from pathlib import Path


class Config:
    """
    Quản lý các đường dẫn và tùy chọn cấu hình của Secret Guard.
    """

    def __init__(self, project_root=None):
        if project_root is None:
            project_root = Path(__file__).resolve().parent.parent

        self.project_root = Path(project_root).resolve()

        self.config_dir = self.project_root / "config"

        self.allowlist_path = self.config_dir / "allowlist.yaml"
        self.rules_path = self.config_dir / "rules.yaml"

        self.dataset_dir = self.project_root / "dataset"

        self.min_secret_length = 4
        self.mask_visible_start = 4
        self.mask_visible_end = 4

    def get_path(self, *parts):
        """
        Lấy đường dẫn bên trong thư mục gốc dự án.
        """
        return self.project_root.joinpath(*parts)

    def ensure_config_directory(self):
        """ 
        Đảm bảo thư mục config tồn tại.
        """ 
        self.config_dir.mkdir(parents=True, exist_ok=True)
        return self.config_dir
