import requests
import urllib3

# Suppress SSL certificate warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class HeaderScanner:
    def __init__(self, target_url):
        self.target_url = target_url
        self.security_headers = {
            "Content-Security-Policy": {
                "description": "Defines which dynamic resources are allowed to load. Helps prevent XSS.",
                "severity": "Medium"
            },
            "X-Frame-Options": {
                "description": "Indicates whether the browser should be allowed to render the page in a frame or iframe. Helps prevent Clickjacking.",
                "severity": "Medium"
            },
            "X-Content-Type-Options": {
                "description": "Prevents the browser from MIME-sniffing a response away from the declared content-type.",
                "severity": "Low"
            },
            "Strict-Transport-Security": {
                "description": "Enforces secure (HTTPS) connections to the server.",
                "severity": "Medium"
            },
            "Referrer-Policy": {
                "description": "Controls how much referrer information is included with requests.",
                "severity": "Low"
            }
        }

    def analyze(self):
        """Analyze headers of the target URL."""
        findings = []
        try:
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Vanguard/1.0"
            }
            response = requests.get(self.target_url, headers=headers, timeout=5, verify=False)
            response_headers = response.headers

            # 1. Check for missing security headers
            for header, info in self.security_headers.items():
                if header not in response_headers:
                    findings.append({
                        "type": "Missing Security Header",
                        "name": header,
                        "description": info["description"],
                        "severity": info["severity"],
                        "impact": f"Lack of {header} might expose the application to client-side attacks.",
                        "remediation": f"Configure the web server to return the '{header}' header."
                    })

            # 2. Check for information disclosure headers
            disclosure_headers = ["Server", "X-Powered-By", "X-AspNet-Version"]
            for header in disclosure_headers:
                if header in response_headers:
                    findings.append({
                        "type": "Information Disclosure",
                        "name": header,
                        "description": f"The response header reveals server software or version details: '{response_headers[header]}'.",
                        "severity": "Low",
                        "impact": f"Attackers can use version information to find target-specific exploits.",
                        "remediation": f"Disable or strip the '{header}' header in the web server configuration."
                    })

            return findings

        except Exception as e:
            return [{
                "type": "Connection Error",
                "name": "Failed to connect",
                "description": f"Could not establish a connection to verify headers: {str(e)}",
                "severity": "High",
                "impact": "The scanner cannot reach the target.",
                "remediation": "Check if the server is up and the URL is correct."
            }]
