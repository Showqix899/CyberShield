class PromptBuilder:

    @staticmethod
    def build(scan):

        prompt = f"""
You are a Senior Cybersecurity Consultant.

Analyze the following scan result.

Target:
{scan.target}

Risk Score:
{scan.risk_score}

SSL Enabled:
{scan.ssl_enabled}

TLS Version:
{scan.tls_version}

Open Ports
"""

        for port in scan.ports.all():

            prompt += f"""

Port: {port.port}

Service: {port.service}

Banner:
{port.banner}
"""

        prompt += """

Detected Vulnerabilities

"""

        for vulnerability in scan.vulnerabilities.all():

            prompt += f"""

Title:
{vulnerability.title}

Severity:
{vulnerability.severity}

Description:
{vulnerability.description}
"""

        prompt += """

DNS Records

"""

        for record in scan.dns_records.all():

            prompt += f"""

{record.record_type}

{record.value}
"""

        prompt += """

Provide:

1. Executive Summary

2. Explain each vulnerability.

3. Explain every open port.

4. Explain insecure SSL configuration.

5. Explain DNS weaknesses.

6. Give step-by-step remediation.

7. Prioritize fixes.

8. Best practices.

Keep the response professional.

Return Markdown.
"""

        return prompt