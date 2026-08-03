import re


class BannerParser:

    PATTERNS = [
        ("Apache", r"Apache/([\d.]+)"),
        ("nginx", r"nginx/([\d.]+)"),
        ("OpenSSH", r"OpenSSH[_/]([\d.]+)"),
        ("PHP", r"PHP/([\d.]+)"),
        ("Microsoft-IIS", r"Microsoft-IIS/([\d.]+)"),
    ]

    def parse(self, banner):

        if not banner:
            return None

        for software, pattern in self.PATTERNS:

            match = re.search(pattern, banner, re.IGNORECASE)

            if match:

                return {
                    "software": software,
                    "version": match.group(1)
                }

        return None