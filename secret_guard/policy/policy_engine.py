
class PolicyEngine:
    """
    Đánh giá mức độ rủi ro của các phát hiện từ Secret Guard.

    PolicyEngine không trực tiếp phát hiện secret.
    Nó nhận kết quả từ các detector/scanner, phân loại mức độ
    nghiêm trọng và đề xuất hành động xử lý.
    """

    DEFAULT_POLICIES = {
        "private key": {
            "severity": "CRITICAL",
            "score": 100,
            "action": "BLOCK",
            "reason": "Phát hiện dấu hiệu khóa riêng tư.",
        },
        "api key": {
            "severity": "HIGH",
            "score": 80,
            "action": "BLOCK",
            "reason": "Phát hiện giá trị có khả năng là API key.",
        },
        "password": {
            "severity": "HIGH",
            "score": 80,
            "action": "BLOCK",
            "reason": "Phát hiện giá trị có khả năng là mật khẩu.",
        },
        "token": {
            "severity": "HIGH",
            "score": 80,
            "action": "BLOCK",
            "reason": "Phát hiện giá trị có khả năng là token.",
        },
        "secret keyword": {
            "severity": "HIGH",
            "score": 80,
            "action": "BLOCK",
            "reason": "Phát hiện giá trị gắn với tên biến nhạy cảm.",
        },
        "base64 high entropy string": {
            "severity": "MEDIUM",
            "score": 60,
            "action": "REVIEW",
            "reason": "Chuỗi Base64 có độ ngẫu nhiên cao.",
        },
        "hex high entropy string": {
            "severity": "MEDIUM",
            "score": 60,
            "action": "REVIEW",
            "reason": "Chuỗi hexadecimal có độ ngẫu nhiên cao.",
        },
        "high entropy": {
            "severity": "MEDIUM",
            "score": 50,
            "action": "REVIEW",
            "reason": "Chuỗi có độ ngẫu nhiên cao, cần kiểm tra thêm.",
        },
    }

    def __init__(self, custom_policies=None):
        """
        custom_policies cho phép bổ sung hoặc ghi đè chính sách.

        Ví dụ:
        {
            "secret keyword": {
                "severity": "CRITICAL",
                "score": 100,
                "action": "BLOCK",
                "reason": "Chính sách tùy chỉnh."
            }
        }
        """
        self.policies = {
            name: policy.copy()
            for name, policy in self.DEFAULT_POLICIES.items()
        }

        if custom_policies:
            for name, policy in custom_policies.items():
                normalized_name = name.strip().lower()

                if normalized_name in self.policies:
                    self.policies[normalized_name].update(policy)
                else:
                    self.policies[normalized_name] = policy.copy()

    def evaluate_finding(self, finding):
        """
        Đánh giá một phát hiện và trả về kết quả kèm chính sách.
        """
        if not isinstance(finding, dict):
            raise TypeError("finding phải là một dictionary.")

        secret_type = finding.get("type", "")
        if not isinstance(secret_type, str):
            secret_type = ""

        normalized_type = secret_type.strip().lower()
        policy = self.policies.get(normalized_type)

        if policy is None:
            policy = {
                "severity": "LOW",
                "score": 20,
                "action": "REVIEW",
                "reason": "Loại phát hiện chưa có chính sách cụ thể.",
            }

        result = finding.copy()
        result.update({
            "severity": policy["severity"],
            "risk_score": policy["score"],
            "action": policy["action"],
            "policy_reason": policy["reason"],
        })

        return result

    def evaluate(self, findings):
        """
        Đánh giá danh sách phát hiện từ SecretScanner.
        """
        if not isinstance(findings, list):
            raise TypeError("findings phải là một list.")

        return [
            self.evaluate_finding(finding)
            for finding in findings
        ]

    def summarize(self, evaluated_findings):
        """
        Tổng hợp số lượng phát hiện theo mức độ nghiêm trọng
        và hành động được đề xuất.
        """
        if not isinstance(evaluated_findings, list):
            raise TypeError(
                "evaluated_findings phải là một list."
            )

        summary = {
            "total": len(evaluated_findings),
            "by_severity": {
                "CRITICAL": 0,
                "HIGH": 0,
                "MEDIUM": 0,
                "LOW": 0,
            },
            "by_action": {
                "BLOCK": 0,
                "REVIEW": 0,
                "ALLOW": 0,
            },
        }

        for finding in evaluated_findings:
            if not isinstance(finding, dict):
                raise TypeError(
                    "Mỗi phần tử phải là một dictionary."
                )

            severity = finding.get("severity", "LOW")
            action = finding.get("action", "REVIEW")

            if severity in summary["by_severity"]:
                summary["by_severity"][severity] += 1

            if action in summary["by_action"]:
                summary["by_action"][action] += 1

        return summary
