import requests


class HeaderScanner:

    SECURITY_HEADERS = [
        "Content-Security-Policy",
        "Strict-Transport-Security",
        "X-Frame-Options",
        "X-Content-Type-Options",
        "Referrer-Policy",
        "Permissions-Policy",
    ]

    def scan(self, target):

        try:

            if not target.startswith(("http://", "https://")):
                url = "https://" + target
            else:
                url = target

            response = requests.get(
                url,
                timeout=5,
                allow_redirects=True,
            )

            return {
                "success": True,
                "headers": response.headers,
            }

        except Exception:

            return {
                "success": False,
                "headers": {},
            }