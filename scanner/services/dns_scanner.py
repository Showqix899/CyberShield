import dns.resolver


class DNSScanner:

    RECORDS = [
        "A",
        "AAAA",
        "MX",
        "NS",
        "TXT",
        "CNAME",
    ]

    def scan(self, domain):

        results = {}

        for record in self.RECORDS:

            try:

                answers = dns.resolver.resolve(domain, record)

                results[record] = [
                    str(answer)
                    for answer in answers
                ]

            except Exception:

                results[record] = []

        return results