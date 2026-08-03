from scanner.models import Scan, PortResult

from .port_scanner import PortScanner
from .banner_scanner import BannerScanner
from .ssl_scanner import SSLScanner
from .risk_analyzer import RiskAnalyzer
from .header_scanner import HeaderScanner
from .dns_scanner import DNSScanner
from scanner.models import DNSRecord
from .banner_parser import BannerParser
from .cvs_scanner import CVEScanner


class ScanEngine:

    def __init__(self):
        self.port_scanner = PortScanner()
        self.banner_scanner = BannerScanner()
        self.ssl_scanner = SSLScanner()
        self.header_scanner = HeaderScanner()
        self.risk_analyzer = RiskAnalyzer()
        self.dns_scanner = DNSScanner()
        self.banner_parser = BannerParser()
        self.cve_scanner = CVEScanner()

    def run(self, user, target):

        # Run Port Scan
        result = self.port_scanner.scan(target)

        if not result["success"]:
            return result

        # Create Scan Record
        scan = Scan.objects.create(
            user=user,
            target=target,
            ip_address=result["ip"],
            scan_type="website",
            status="completed",
        )

        # SSL Scan
        ssl_info = self.ssl_scanner.scan(target)

        if ssl_info["enabled"]:
            scan.ssl_enabled = True
            scan.ssl_issuer = ssl_info["issuer"]
            scan.ssl_expiry = ssl_info["expires"]
            scan.tls_version = ssl_info["tls"]

        # HTTP Header Scan
        header_result = self.header_scanner.scan(target)
        
        dns_results = self.dns_scanner.scan(target)
        
        for record_type, values in dns_results.items():

            for value in values:

                DNSRecord.objects.create(
                    scan=scan,
                    record_type=record_type,
                    value=value,
                )

        # Save Open Ports
        for port in result["ports"]:

            banner = self.banner_scanner.scan(
                result["ip"],
                port["port"],
            )

            port_result=PortResult.objects.create(
                scan=scan,
                port=port["port"],
                service=port["service"],
                banner=banner,
            )
            
            parsed = self.banner_parser.parse(banner)

            if parsed:

                cves = self.cve_scanner.find_cves(
                    parsed["software"],
                    parsed["version"],
                )

                for cve in cves:

                    from scanner.models import Vulnerability

                    Vulnerability.objects.create(
                        scan=scan,
                        title=f"{parsed['software']} {parsed['version']} Vulnerability",
                        severity=cve.severity,
                        description=f"{cve.cve_id}: {cve.description}",
                        recommendation=cve.recommendation,
                        port=port_result.port,
                        service=parsed["software"],
                    )

        # Save Scan Updates
        scan.save()

        # Risk Analysis
        self.risk_analyzer.analyze(
            scan,
            headers=header_result.get("headers", {})
        )
        
        return {
            "success": True,
            "scan": scan,
        }