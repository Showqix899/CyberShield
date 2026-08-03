import socket


class BannerScanner:

    def scan(self, host, port):

        try:

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            sock.settimeout(3)

            sock.connect((host, port))

            if port in [80, 8080]:

                request = (
                    "HEAD / HTTP/1.1\r\n"
                    f"Host: {host}\r\n"
                    "Connection: close\r\n\r\n"
                )

                sock.send(request.encode())

            banner = sock.recv(1024).decode(
                errors="ignore"
            )

            sock.close()

            return banner

        except Exception:

            return ""