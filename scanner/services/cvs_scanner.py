from scanner.models import CVE


class CVEScanner:

    def find_cves(self, software, version):

        return CVE.objects.filter(
            software__iexact=software,
            version=version,
        )