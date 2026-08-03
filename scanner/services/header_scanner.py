# import requests


# class HeaderScanner:

#     SECURITY_HEADERS = [
#         "Content-Security-Policy",
#         "Strict-Transport-Security",
#         "X-Frame-Options",
#         "X-Content-Type-Options",
#         "Referrer-Policy",
#         "Permissions-Policy",
#     ]

#     def scan(self, target):

#         try:

#             if not target.startswith(("http://", "https://")):
#                 url = "https://" + target
#             else:
#                 url = target

#             response = requests.get(
#                 url,
#                 timeout=5,
#                 allow_redirects=True,
#             )

#             return {
#                 "success": True,
#                 "headers": response.headers,
#             }

#         except Exception:

#             return {
#                 "success": False,
#                 "headers": {},
#             }



import requests
from typing import Dict, Any, Optional, List, Tuple
from urllib.parse import urlparse
import logging


class HeaderScanner:
    """
    A security header scanner that checks for presence and proper configuration
    of essential security headers in HTTP responses.
    """

    SECURITY_HEADERS = [
        "Content-Security-Policy",
        "Strict-Transport-Security",
        "X-Frame-Options",
        "X-Content-Type-Options",
        "Referrer-Policy",
        "Permissions-Policy",
        "X-XSS-Protection",
        "Cache-Control",
        "Pragma",
    ]

    # Define expected values/patterns for validation
    HEADER_EXPECTATIONS = {
        "Strict-Transport-Security": {
            "required": True,
            "min_age": 31536000,  # 1 year in seconds
            "include_subdomains": True,
        },
        "X-Frame-Options": {
            "required": True,
            "valid_values": ["DENY", "SAMEORIGIN"],
        },
        "X-Content-Type-Options": {
            "required": True,
            "valid_values": ["nosniff"],
        },
        "Referrer-Policy": {
            "required": False,
            "recommended": ["strict-origin-when-cross-origin", "no-referrer"],
        },
    }

    def __init__(self, timeout: int = 10, verify_ssl: bool = True, 
                 user_agent: Optional[str] = None):
        """
        Initialize the HeaderScanner with configuration options.
        
        Args:
            timeout: Request timeout in seconds
            verify_ssl: Whether to verify SSL certificates
            user_agent: Custom User-Agent string
        """
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.user_agent = user_agent or "HeaderScanner/1.0"
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": self.user_agent})

    def scan(self, target: str) -> Dict[str, Any]:
        """
        Scan a target URL for security headers.
        
        Args:
            target: URL or domain to scan (e.g., 'example.com' or 'https://example.com')
            
        Returns:
            Dictionary containing scan results with headers and analysis
        """
        try:
            # Validate and normalize URL
            url = self._normalize_url(target)
            
            # Send request
            response = self.session.get(
                url,
                timeout=self.timeout,
                allow_redirects=True,
                verify=self.verify_ssl,
            )
            
            # Analyze headers
            headers_analysis = self._analyze_headers(response.headers)
            
            return {
                "success": True,
                "url": url,
                "status_code": response.status_code,
                "headers": dict(response.headers),
                "security_headers_analysis": headers_analysis,
                "score": self._calculate_score(headers_analysis),
                "recommendations": self._generate_recommendations(headers_analysis),
            }
            
        except requests.exceptions.Timeout:
            return self._error_response(f"Timeout error - server did not respond within {self.timeout} seconds")
        except requests.exceptions.ConnectionError:
            return self._error_response("Connection error - unable to reach the server")
        except requests.exceptions.SSLError:
            return self._error_response("SSL certificate verification failed")
        except requests.exceptions.TooManyRedirects:
            return self._error_response("Too many redirects")
        except Exception as e:
            return self._error_response(f"Unexpected error: {str(e)}")

    def _normalize_url(self, target: str) -> str:
        """Normalize the target URL."""
        if not target.startswith(("http://", "https://")):
            # Default to HTTPS for security
            url = "https://" + target
        else:
            url = target
        return url

    def _analyze_headers(self, headers: Dict[str, str]) -> Dict[str, Dict[str, Any]]:
        """Analyze security headers for presence and configuration."""
        analysis = {}
        headers_lower = {k.lower(): v for k, v in headers.items()}

        for header in self.SECURITY_HEADERS:
            header_lower = header.lower()
            found = header_lower in headers_lower
            value = headers_lower.get(header_lower, "")

            analysis[header] = {
                "present": found,
                "value": value if found else None,
                "valid": self._validate_header(header, value) if found else False,
                "recommendation": self._get_recommendation(header, found, value),
            }

        return analysis

    def _validate_header(self, header: str, value: str) -> bool:
        """Validate if a header's value meets security best practices."""
        expectations = self.HEADER_EXPECTATIONS.get(header)
        if not expectations:
            return True  # No validation defined

        # Check if required
        if expectations.get("required", False) and not value:
            return False

        # Validate Strict-Transport-Security
        if header == "Strict-Transport-Security":
            if "max-age=" not in value:
                return False
            try:
                # Extract max-age value
                for part in value.split(";"):
                    part = part.strip()
                    if part.startswith("max-age="):
                        max_age = int(part.split("=")[1])
                        if max_age < expectations["min_age"]:
                            return False
            except ValueError:
                return False
            return True

        # Validate X-Frame-Options
        if header == "X-Frame-Options":
            return value in expectations["valid_values"]

        # Validate X-Content-Type-Options
        if header == "X-Content-Type-Options":
            return value.lower() == "nosniff"

        # Validate Referrer-Policy
        if header == "Referrer-Policy":
            # Check if it's one of the recommended policies
            return value in expectations.get("recommended", [])

        return True

    def _get_recommendation(self, header: str, found: bool, value: str) -> str:
        """Generate a recommendation for a header."""
        if found:
            if self._validate_header(header, value):
                return "OK - Properly configured"
            else:
                return f"⚠️ Present but misconfigured. Recommended: {self._get_expected_value(header)}"
        else:
            return f"❌ Missing. Recommended: Set '{header}' header."

    def _get_expected_value(self, header: str) -> str:
        """Get the expected/recommended value for a header."""
        expectations = self.HEADER_EXPECTATIONS.get(header)
        if not expectations:
            return ""

        if header == "Strict-Transport-Security":
            return f"max-age={expectations['min_age']}; includeSubDomains"
        elif header == "X-Frame-Options":
            return "DENY"
        elif header == "X-Content-Type-Options":
            return "nosniff"
        elif header == "Referrer-Policy":
            return "strict-origin-when-cross-origin"
        return ""

    def _calculate_score(self, analysis: Dict[str, Dict[str, Any]]) -> int:
        """Calculate a security score based on header analysis."""
        if not analysis:
            return 0

        total_headers = len(analysis)
        present_headers = sum(1 for h in analysis.values() if h["present"])
        valid_headers = sum(1 for h in analysis.values() if h.get("valid", False))

        # Weight: presence 50%, correctness 50%
        presence_score = (present_headers / total_headers) * 50
        correctness_score = (valid_headers / total_headers) * 50

        return int(presence_score + correctness_score)

    def _generate_recommendations(self, analysis: Dict[str, Dict[str, Any]]) -> List[str]:
        """Generate a list of actionable recommendations."""
        recommendations = []
        
        for header, data in analysis.items():
            if not data["present"]:
                recommendations.append(
                    f"Add '{header}' header to enhance security."
                )
            elif not data["valid"]:
                expected = self._get_expected_value(header)
                if expected:
                    recommendations.append(
                        f"Update '{header}' header to: {expected}"
                    )
        
        if not recommendations:
            recommendations.append("✅ All security headers are properly configured!")
        
        return recommendations

    def _error_response(self, error_message: str) -> Dict[str, Any]:
        """Create an error response dictionary."""
        return {
            "success": False,
            "error": error_message,
            "headers": {},
            "security_headers_analysis": {},
            "score": 0,
            "recommendations": [f"❌ Scan failed: {error_message}"],
        }

    def scan_multiple(self, targets: List[str]) -> Dict[str, Any]:
        """Scan multiple targets and return aggregated results."""
        results = {}
        for target in targets:
            results[target] = self.scan(target)
        return results

    def check_redirect_chain(self, target: str) -> List[Tuple[str, int]]:
        """Check the redirect chain of a URL."""
        try:
            url = self._normalize_url(target)
            response = self.session.get(
                url,
                timeout=self.timeout,
                allow_redirects=True,
                verify=self.verify_ssl,
            )
            
            redirect_chain = []
            for resp in response.history:
                redirect_chain.append((resp.url, resp.status_code))
            redirect_chain.append((response.url, response.status_code))
            
            return redirect_chain
        except Exception:
            return []