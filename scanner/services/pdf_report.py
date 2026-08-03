from io import BytesIO

from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
)


class PDFReport:

    def generate(self, scan):

        buffer = BytesIO()

        doc = SimpleDocTemplate(buffer)

        styles = getSampleStyleSheet()

        elements = []

        elements.append(
            Paragraph(
                "<b>CyberShield Vulnerability Assessment Report</b>",
                styles["Title"],
            )
        )

        elements.append(Spacer(1, 20))

        elements.append(
            Paragraph(f"<b>Target:</b> {scan.target}", styles["Normal"])
        )

        elements.append(
            Paragraph(f"<b>IP Address:</b> {scan.ip_address}", styles["Normal"])
        )

        elements.append(
            Paragraph(f"<b>Status:</b> {scan.status}", styles["Normal"])
        )

        elements.append(
            Paragraph(f"<b>Risk Score:</b> {scan.risk_score}/100", styles["Normal"])
        )

        elements.append(Spacer(1, 15))

        elements.append(
            Paragraph("<b>Open Ports</b>", styles["Heading2"])
        )

        for port in scan.ports.all():

            elements.append(
                Paragraph(
                    f"{port.port} - {port.service}",
                    styles["Normal"],
                )
            )

        elements.append(Spacer(1, 15))

        elements.append(
            Paragraph("<b>SSL Information</b>", styles["Heading2"])
        )

        if scan.ssl_enabled:

            elements.append(
                Paragraph(
                    f"TLS Version: {scan.tls_version}",
                    styles["Normal"],
                )
            )

            elements.append(
                Paragraph(
                    f"Issuer: {scan.ssl_issuer}",
                    styles["Normal"],
                )
            )

            elements.append(
                Paragraph(
                    f"Expires: {scan.ssl_expiry}",
                    styles["Normal"],
                )
            )

        else:

            elements.append(
                Paragraph(
                    "HTTPS Not Enabled",
                    styles["Normal"],
                )
            )

        elements.append(Spacer(1, 15))

        elements.append(
            Paragraph("<b>DNS Records</b>", styles["Heading2"])
        )

        for record in scan.dns_records.all():

            elements.append(
                Paragraph(
                    f"{record.record_type}: {record.value}",
                    styles["Normal"],
                )
            )

        elements.append(Spacer(1, 15))

        elements.append(
            Paragraph(
                "<b>Detected Vulnerabilities</b>",
                styles["Heading2"],
            )
        )

        vulnerabilities = scan.vulnerabilities.all()

        if vulnerabilities.exists():

            for vuln in vulnerabilities:

                elements.append(
                    Paragraph(
                        f"<b>{vuln.severity}</b> - {vuln.title}",
                        styles["Normal"],
                    )
                )

                elements.append(
                    Paragraph(
                        vuln.description,
                        styles["Normal"],
                    )
                )

                elements.append(
                    Paragraph(
                        f"Recommendation: {vuln.recommendation}",
                        styles["Normal"],
                    )
                )

                elements.append(Spacer(1, 10))

        else:

            elements.append(
                Paragraph(
                    "No vulnerabilities detected.",
                    styles["Normal"],
                )
            )

        doc.build(elements)

        pdf = buffer.getvalue()

        buffer.close()

        return pdf