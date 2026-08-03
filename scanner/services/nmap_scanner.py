import nmap


class NmapScanner:

    def __init__(self):
        self.nm = nmap.PortScanner()

    def scan(self, target):

        self.nm.scan(
            hosts=target,
            arguments="-sV"
        )

        results = []

        for host in self.nm.all_hosts():

            protocols = self.nm[host].all_protocols()

            for proto in protocols:

                ports = self.nm[host][proto]

                for port in sorted(ports):

                    service = ports[port]

                    results.append({
                        "port": port,
                        "state": service.get("state", ""),
                        "service": service.get("name", ""),
                        "product": service.get("product", ""),
                        "version": service.get("version", ""),
                    })

        return results