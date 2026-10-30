
import re


class RegexDetector:
    """
    Phát hiện các chuỗi có khả năng là secret
    bằng cách sử dụng biểu thức chính quy.
    """

    def __init__(self):
        self.patterns = {
            "API Key": re.compile(
                r"""(?i)\bapi[_-]?key\b\s*[:=]\s*["']([^"'\s]{8,})["']"""
            ),

            "Password": re.compile(
                r"""(?i)(?:\bpassword\b\s*[:=]\s*["']?([^"'\s,;]+)|(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis)://[^:/@\s]+:([^"'@\s/]+))"""
            ),

            "Token": re.compile(
                r"""(?i)\b(?:user[_-])?(?:access[_-]?token|auth[_-]?token|refresh[_-]?token|jwt[_-]?token|bearer[_-]?token|session[_-]?token|oauth[_-]?token|id[_-]?token|private[_-]?token|token)\b\s*[:=]\s*["']([^"'\s]{8,})["']"""
            ),

            "Private Key": re.compile(
                r"""-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----"""
            ),
        }

    def detect(self, text):
        """
        Nhận nội dung văn bản và tìm các secret nghi ngờ.

        Args:
            text (str): Nội dung cần kiểm tra.

        Returns:
            list: Danh sách các kết quả phát hiện.
        """

        findings = []

        if not isinstance(text, str):
            return findings

        for secret_type, pattern in self.patterns.items():
            for match in pattern.finditer(text):

                if secret_type == "Private Key":
                    secret_value = match.group(0)
                    start = match.start()
                    end = match.end()

                else:
                    if secret_type == "Password":
                        secret_value = match.group(1) or match.group(2)
                        group_index = 1 if match.group(1) else 2
                    else:
                        secret_value = match.group(1)
                        group_index = 1

                    if not secret_value:
                        continue

                    start = match.start(group_index)
                    end = match.end(group_index)

                findings.append({
                    "type": secret_type,
                    "secret": secret_value,
                    "start": start,
                    "end": end,
                })

        return findings
