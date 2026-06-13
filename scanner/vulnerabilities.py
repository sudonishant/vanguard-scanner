import requests
from bs4 import BeautifulSoup
import urllib3
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

# Suppress SSL certificate warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class VulnerabilityScanner:
    def __init__(self):
        # Payloads to inject
        self.xss_payloads = [
            "<script>alert('VanguardXSS')</script>",
            '"><script>alert(1)</script>',
            "<img src=x onerror=alert('VanguardXSS')>",
            "javascript:alert(1)"
        ]
        
        self.sql_payloads = [
            "'",
            "\"",
            "1' OR '1'='1",
            "1\" OR \"1\"=\"1",
            "admin' --",
            "admin' #"
        ]
        
        # Common database error messages
        self.sql_errors = [
            "SQL syntax",
            "mysql_fetch",
            "MySQLQueryException",
            "MariaDB",
            "PostgreSQL query failed",
            "pg_query",
            "SQLite/JDBCDriver",
            "sqlite3.OperationalError",
            "Microsoft OLE DB Provider for SQL Server",
            "SQLServerException",
            "Oracle error",
            "quoted string not properly terminated",
            "driver",
            "execute query"
        ]
        
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Vanguard/1.0"
        }

    def test_url_parameters(self, url):
        """Test URL parameters (GET) for XSS and SQL Injection."""
        findings = []
        parsed = urlparse(url)
        query_params = parse_qs(parsed.query)

        if not query_params:
            return findings

        # Test each parameter individually
        for param in query_params:
            # 1. Test for XSS
            for payload in self.xss_payloads:
                # Construct query with payload
                modified_query = query_params.copy()
                modified_query[param] = [payload]
                
                # Rebuild URL
                query_string = urlencode(modified_query, doseq=True)
                test_url = urlunparse(parsed._replace(query=query_string))

                try:
                    res = requests.get(test_url, headers=self.headers, timeout=5, verify=False)
                    if payload in res.text:
                        findings.append({
                            "type": "Cross-Site Scripting (XSS)",
                            "name": f"Reflected XSS in query param: '{param}'",
                            "severity": "High",
                            "url": url,
                            "parameter": param,
                            "payload": payload,
                            "method": "GET",
                            "description": f"The parameter '{param}' is reflected back in the page content without proper sanitization/escaping, allowing script injection.",
                            "impact": "Attackers can execute arbitrary JavaScript in the victim's browser session, stealing session cookies or redirecting users.",
                            "remediation": "Sanitize and html-escape all user inputs before displaying them on the page. Implement a robust Content Security Policy (CSP)."
                        })
                        break  # Found XSS for this param, move to next
                except Exception:
                    pass

            # 2. Test for SQLi
            for payload in self.sql_payloads:
                modified_query = query_params.copy()
                modified_query[param] = [payload]
                
                query_string = urlencode(modified_query, doseq=True)
                test_url = urlunparse(parsed._replace(query=query_string))

                try:
                    res = requests.get(test_url, headers=self.headers, timeout=5, verify=False)
                    for error in self.sql_errors:
                        if error.lower() in res.text.lower():
                            findings.append({
                                "type": "SQL Injection (SQLi)",
                                "name": f"SQL Error Injection in query param: '{param}'",
                                "severity": "Critical",
                                "url": url,
                                "parameter": param,
                                "payload": payload,
                                "method": "GET",
                                "description": f"Injecting SQL syntax characters into '{param}' triggered a database error message: '{error}'. This indicates raw inputs are likely passed directly into database queries.",
                                "impact": "Attackers can bypass authentication, read/modify sensitive data from the database, or potentially run shell commands on the server.",
                                "remediation": "Use parameterized queries (prepared statements) for all database operations. Never concatenate user inputs directly into SQL strings."
                            })
                            break
                    else:
                        continue
                    break # Break outer loop if finding was registered
                except Exception:
                    pass
        
        return findings

    def test_form(self, form):
        """Test forms (GET/POST) for XSS and SQL Injection."""
        findings = []
        action_url = form["action"]
        method = form["method"]
        inputs = form["inputs"]

        if not inputs:
            return findings

        # Test each input field individually
        for target_input in inputs:
            input_name = target_input["name"]
            
            # Skip submit, buttons, etc.
            if target_input["type"] in ["submit", "button"]:
                continue

            # 1. Test XSS in Form
            for payload in self.xss_payloads:
                data = {}
                for inp in inputs:
                    if inp["name"] == input_name:
                        data[inp["name"]] = payload
                    else:
                        data[inp["name"]] = "test"

                try:
                    if method == "post":
                        res = requests.post(action_url, data=data, headers=self.headers, timeout=5, verify=False)
                    else:
                        res = requests.get(action_url, params=data, headers=self.headers, timeout=5, verify=False)

                    if payload in res.text:
                        findings.append({
                            "type": "Cross-Site Scripting (XSS)",
                            "name": f"Form Reflected XSS in input: '{input_name}'",
                            "severity": "High",
                            "url": form["url"],
                            "parameter": input_name,
                            "payload": payload,
                            "method": method.upper(),
                            "description": f"The form field '{input_name}' is reflected back in the page content without proper sanitization, allowing script injection.",
                            "impact": "Attackers can execute arbitrary scripts in the context of the user session.",
                            "remediation": "HTML-encode and sanitize all user input before outputting it back to the client."
                        })
                        break
                except Exception:
                    pass

            # 2. Test SQL Injection in Form
            for payload in self.sql_payloads:
                data = {}
                for inp in inputs:
                    if inp["name"] == input_name:
                        data[inp["name"]] = payload
                    else:
                        data[inp["name"]] = "test"

                try:
                    if method == "post":
                        res = requests.post(action_url, data=data, headers=self.headers, timeout=5, verify=False)
                    else:
                        res = requests.get(action_url, params=data, headers=self.headers, timeout=5, verify=False)

                    for error in self.sql_errors:
                        if error.lower() in res.text.lower():
                            findings.append({
                                "type": "SQL Injection (SQLi)",
                                "name": f"SQL Error Injection in form input: '{input_name}'",
                                "severity": "Critical",
                                "url": form["url"],
                                "parameter": input_name,
                                "payload": payload,
                                "method": method.upper(),
                                "description": f"Injecting SQL payload into form field '{input_name}' triggered a database error message: '{error}'.",
                                "impact": "Allows full/partial access to read or write database records, bypassing logins.",
                                "remediation": "Implement parameterized queries/prepared statements in backend code."
                            })
                            break
                    else:
                        continue
                    break
                except Exception:
                    pass

        return findings
