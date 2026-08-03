import socket
import ssl
from datetime import datetime


class SSLScanner:

    def scan(self, host):

        try:

            context = ssl.create_default_context()

            with socket.create_connection((host, 443), timeout=5) as sock:

                with context.wrap_socket(
                    sock,
                    server_hostname=host,
                ) as secure_socket:

                    cert = secure_socket.getpeercert()

                    issuer = dict(
                        x[0] for x in cert["issuer"]
                    )["organizationName"]

                    expire_date = datetime.strptime(
                        cert["notAfter"],
                        "%b %d %H:%M:%S %Y %Z"
                    )

                    return {
                        "enabled": True,
                        "issuer": issuer,
                        "expires": expire_date,
                        "tls": secure_socket.version(),
                    }

        except Exception:

            return {
                "enabled": False
            }