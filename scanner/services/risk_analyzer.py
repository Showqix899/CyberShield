from scanner.models import Vulnerability


class RiskAnalyzer:

    def analyze(self,scan,headers=None):

        score = 0

        # Analyze open ports
        for port in scan.ports.all():

            if port.port == 21:
                Vulnerability.objects.create(
                    scan=scan,
                    title="FTP Service Detected",
                    severity="Medium",
                    description="FTP sends data without encryption.",
                    recommendation="Use SFTP or FTPS instead.",
                    port=21,
                    service="FTP",
                )
                score += 20

            elif port.port == 23:
                Vulnerability.objects.create(
                    scan=scan,
                    title="Telnet Service Detected",
                    severity="High",
                    description="Telnet transmits usernames and passwords in plain text.",
                    recommendation="Disable Telnet and use SSH.",
                    port=23,
                    service="Telnet",
                )
                score += 40

            elif port.port == 3389:
                Vulnerability.objects.create(
                    scan=scan,
                    title="Remote Desktop Exposed",
                    severity="Medium",
                    description="Remote Desktop Protocol is exposed to the network.",
                    recommendation="Restrict access with a firewall or VPN.",
                    port=3389,
                    service="RDP",
                )
                score += 25

        # Analyze SSL
        if not scan.ssl_enabled:
            Vulnerability.objects.create(
                scan=scan,
                title="HTTPS Not Enabled",
                severity="Medium",
                description="The website does not provide HTTPS.",
                recommendation="Install an SSL/TLS certificate.",
            )
            score += 20
            
        if headers:

            required_headers = [
                "Content-Security-Policy",
                "Strict-Transport-Security",
                "X-Frame-Options",
                "X-Content-Type-Options",
                "Referrer-Policy",
                "Permissions-Policy",
            ]

            for header in required_headers:

                if header not in headers:

                    Vulnerability.objects.create(
                        scan=scan,
                        title=f"Missing {header}",
                        severity="Low",
                        description=f"The HTTP response does not include the {header} security header.",
                        recommendation=f"Configure the {header} header on the web server.",
                    )

                    score += 5
                    
        for vulnerability in scan.vulnerabilities.all():

            severity = vulnerability.severity.lower()

            if severity == "critical":
                score += 40

            elif severity == "high":
                score += 30

            elif severity == "medium":
                score += 15

            elif severity == "low":
                score += 5

        scan.risk_score = min(score, 100)
        scan.save()