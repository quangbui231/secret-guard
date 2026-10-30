
class SecretMasker:
    """
    Che giấu giá trị secret trước khi hiển thị trong báo cáo.

    Ví dụ:
    AKIAIOSFODNN7EXAMPLE -> AKIA************MPLE
    """

    def __init__(self, visible_start=4, visible_end=4):
        if not isinstance(visible_start, int) or isinstance(visible_start, bool):
            raise TypeError("visible_start phải là số nguyên.")

        if not isinstance(visible_end, int) or isinstance(visible_end, bool):
            raise TypeError("visible_end phải là số nguyên.")

        if visible_start < 0 or visible_end < 0:
            raise ValueError("Số ký tự hiển thị không được âm.")

        self.visible_start = visible_start
        self.visible_end = visible_end

    def mask(self, secret):
        """
        Che phần giữa của secret, chỉ giữ lại một phần đầu và cuối.
        """
        if not isinstance(secret, str):
            raise TypeError("secret phải là chuỗi.")

        if not secret:
            return ""

        total_visible = self.visible_start + self.visible_end

        if len(secret) <= total_visible:
            return "*" * len(secret)

        start = secret[:self.visible_start] if self.visible_start else ""
        end = secret[-self.visible_end:] if self.visible_end else ""

        hidden_length = len(secret) - total_visible

        return start + ("*" * hidden_length) + end
