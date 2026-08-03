import socket

COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    3306: "MySQL",
    8080: "HTTP-Alt",
}


class PortScanner:

    def scan(self, host):

        open_ports = []

        try:
            ip = socket.gethostbyname(host)
        except socket.gaierror:
            return {
                "success": False,
                "message": "Invalid Host"
            }

        for port, service in COMMON_PORTS.items():

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            sock.settimeout(0.5)

            result = sock.connect_ex((ip, port))

            if result == 0:

                open_ports.append({
                    "port": port,
                    "service": service
                })

            sock.close()

        return {
            "success": True,
            "ip": ip,
            "ports": open_ports
        }