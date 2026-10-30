
from secret_guard.reporting.masker import SecretMasker


class Reporter:
    """
    Tạo báo cáo kết quả phát hiện secret.

    Hỗ trợ:
    - Hiển thị kết quả trên terminal.
    - Che giá trị secret trước khi hiển thị.
    - Hiển thị các detector đã phát hiện.
    - Thống kê số lượng phát hiện theo mức độ rủi ro.
    """

    def __init__(self, masker=None):
        self.masker = masker or SecretMasker()

    def _format_finding(self, finding):
        secret = finding.get("secret", "")
        masked_secret = self.masker.mask(secret)

        lines = [
            f"[{finding.get('severity', 'UNKNOWN')}] "
            f"{finding.get('type', 'Unknown')}",
            f"File: {finding.get('filename', 'Unknown')}",
            f"Line: {finding.get('line', 'Unknown')}",
            f"Secret: {masked_secret}",
        ]

        # Hiển thị các detector đã phát hiện secret.
        detected_by = finding.get("detected_by", [])

        if detected_by:
            lines.append(
                f"Detected by: {', '.join(detected_by)}"
            )

        lines.extend([
            f"Risk score: {finding.get('risk_score', 'N/A')}",
            f"Action: {finding.get('action', 'REVIEW')}",
            f"Reason: {finding.get('policy_reason', 'N/A')}",
        ])

        return lines

    def generate_report(self, findings):
        if not isinstance(findings, list):
            raise TypeError("findings phải là một list.")

        lines = [
            "=" * 60,
            "             SECRET GUARD - SCAN REPORT",
            "=" * 60,
            f"Total findings: {len(findings)}",
            "",
        ]

        if not findings:
            lines.append("No secrets detected.")
        else:
            for index, finding in enumerate(findings, start=1):
                if not isinstance(finding, dict):
                    raise TypeError(
                        "Mỗi phát hiện phải là một dictionary."
                    )

                lines.append(f"Finding #{index}")
                lines.extend(self._format_finding(finding))
                lines.append("-" * 60)

        return "\n".join(lines)

    def print_report(self, findings):
        report = self.generate_report(findings)
        print(report)
        return report
