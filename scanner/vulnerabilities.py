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

        self.lfi_payloads = [
            "../../../../etc/passwd",
            "..\\..\\..\\..\\windows\\win.ini"
        ]
        
        self.cmd_payloads = [
            ";cat /etc/passwd",
            ";ipconfig",
            "|dir"
        ]
        
        self.ssti_payloads = [
            "{{7*7}}",
            "${7*7}",
            "{{7+'7'}}"
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

            # 3. Test for LFI
            for payload in self.lfi_payloads:
                modified_query = query_params.copy()
                modified_query[param] = [payload]
                
                query_string = urlencode(modified_query, doseq=True)
                test_url = urlunparse(parsed._replace(query=query_string))

                try:
                    res = requests.get(test_url, headers=self.headers, timeout=5, verify=False)
                    if "root:x:" in res.text or "[extensions]" in res.text or "[fonts]" in res.text:
                        findings.append({
                            "type": "Local File Inclusion (LFI)",
                            "name": f"LFI in query param: '{param}'",
                            "severity": "High",
                            "url": url,
                            "parameter": param,
                            "payload": payload,
                            "method": "GET",
                            "description": f"Injecting file inclusion characters into '{param}' retrieved local system files. This indicates that file path inputs are read without proper sanitization.",
                            "impact": "Attackers can read sensitive local files, such as configurations, credentials, or system logs, potentially leading to remote code execution.",
                            "remediation": "Do not pass user inputs directly to file system operations. Use a strict allowlist of permitted files or refer to files by index keys."
                        })
                        break
                except Exception:
                    pass

            # 4. Test for Command Injection
            for payload in self.cmd_payloads:
                modified_query = query_params.copy()
                modified_query[param] = [payload]
                
                query_string = urlencode(modified_query, doseq=True)
                test_url = urlunparse(parsed._replace(query=query_string))

                try:
                    res = requests.get(test_url, headers=self.headers, timeout=5, verify=False)
                    if "root:x:" in res.text or "Windows IP Configuration" in res.text or "<DIR>" in res.text:
                        findings.append({
                            "type": "OS Command Injection",
                            "name": f"Command Injection in query param: '{param}'",
                            "severity": "Critical",
                            "url": url,
                            "parameter": param,
                            "payload": payload,
                            "method": "GET",
                            "description": f"Injecting command shell operators into '{param}' resulted in the execution of system commands. Response matched known system command signatures.",
                            "impact": "Allows attackers to run arbitrary system shell commands with the privileges of the web application service account.",
                            "remediation": "Avoid invoking shell processes directly. Use programming APIs instead. Filter inputs using strict regex validation if shell utilities must be used."
                        })
                        break
                except Exception:
                    pass
            # 5. Test Command Injection in Form / Query (wait, let's keep name consistent - 5. Test for SSTI)
            for payload in self.ssti_payloads:
                modified_query = query_params.copy()
                modified_query[param] = [payload]
                
                query_string = urlencode(modified_query, doseq=True)
                test_url = urlunparse(parsed._replace(query=query_string))

                try:
                    res = requests.get(test_url, headers=self.headers, timeout=5, verify=False)
                    if "49" in res.text or "77" in res.text:
                        findings.append({
                            "type": "Server-Side Template Injection (SSTI)",
                            "name": f"SSTI in query param: '{param}'",
                            "severity": "High",
                            "url": url,
                            "parameter": param,
                            "payload": payload,
                            "method": "GET",
                            "description": f"Injecting template engine expressions into '{param}' resulted in evaluation on the server side (response contains evaluated value).",
                            "impact": "Can lead to full remote code execution (RCE) on the server, permitting full takeover of the server environment.",
                            "remediation": "Do not pass user inputs directly to template rendering engines. Use context-aware escaping, or treat user inputs as data parameters instead of executable code."
                        })
                        break
                except Exception:
                    pass
        
        return findings

    def test_form(self, form):
        """Test forms (GET/POST) for XSS and SQL Injection."""
        findings = []
        action_url = form["action"]
        method = form["method"].lower()
        raw_inputs = form["inputs"]
        # Filter out inputs that do not have a name (we cannot inject into nameless inputs, and this avoids KeyError)
        inputs = [inp for inp in raw_inputs if inp.get("name")]

        if not inputs:
            return findings

        # Check for CSRF protection in POST forms
        if method == "post":
            has_csrf = False
            csrf_names = ["csrf", "xsrf", "token", "authenticity", "secure"]
            for inp in inputs:
                inp_name_lower = inp.get("name", "").lower()
                inp_type = inp.get("type", "").lower()
                if inp_type == "hidden" and any(token_name in inp_name_lower for token_name in csrf_names):
                    has_csrf = True
                    break
            
            if not has_csrf:
                findings.append({
                    "type": "Cross-Site Request Forgery (CSRF)",
                    "name": f"Missing CSRF Token in POST form: Action '{action_url}'",
                    "severity": "Medium",
                    "url": form["url"],
                    "parameter": "N/A",
                    "payload": "N/A",
                    "method": "POST",
                    "description": "The POST form does not contain any hidden anti-CSRF token. This permits attackers to submit state-changing actions on behalf of authenticated users.",
                    "impact": "Attackers can perform unauthorized actions (e.g. changing passwords, updating email settings) on behalf of users if they visit a malicious site.",
                    "remediation": "Implement unique, cryptographically secure anti-CSRF tokens for all state-changing forms. Validate this token on the server side before executing actions."
                })

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

            # 3. Test LFI in Form
            for payload in self.lfi_payloads:
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

                    if "root:x:" in res.text or "[extensions]" in res.text or "[fonts]" in res.text:
                        findings.append({
                            "type": "Local File Inclusion (LFI)",
                            "name": f"Form LFI in input: '{input_name}'",
                            "severity": "High",
                            "url": form["url"],
                            "parameter": input_name,
                            "payload": payload,
                            "method": method.upper(),
                            "description": f"The form field '{input_name}' is vulnerable to Local File Inclusion, permitting access to sensitive system files.",
                            "impact": "Attackers can expose configuration files, environment secrets, or code files from the target machine.",
                            "remediation": "Ensure database and file accesses utilize parameterized models rather than concatenating user input paths."
                        })
                        break
                except Exception:
                    pass

            # 4. Test Command Injection in Form
            for payload in self.cmd_payloads:
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

                    if "root:x:" in res.text or "Windows IP Configuration" in res.text or "<DIR>" in res.text:
                        findings.append({
                            "type": "OS Command Injection",
                            "name": f"Form Command Injection in input: '{input_name}'",
                            "severity": "Critical",
                            "url": form["url"],
                            "parameter": input_name,
                            "payload": payload,
                            "method": method.upper(),
                            "description": f"Injecting command shell operators into form field '{input_name}' resulted in code execution.",
                            "impact": "Allows full server control, enabling data breach, pivot attacks, or ransomware.",
                            "remediation": "Do not pass user inputs to shell commands or sub-processes without strict regex validation or system sandboxing."
                        })
                        break
                except Exception:
                    pass

            # 5. Test SSTI in Form
            for payload in self.ssti_payloads:
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

                    if "49" in res.text or "77" in res.text:
                        findings.append({
                            "type": "Server-Side Template Injection (SSTI)",
                            "name": f"Form SSTI in input: '{input_name}'",
                            "severity": "High",
                            "url": form["url"],
                            "parameter": input_name,
                            "payload": payload,
                            "method": method.upper(),
                            "description": f"Injecting template engine expressions into form field '{input_name}' resulted in evaluation on the server side (response contains evaluated value).",
                            "impact": "Can lead to full remote code execution (RCE) on the server, permitting full takeover of the server environment.",
                            "remediation": "Do not pass user inputs directly to template rendering engines. Use context-aware escaping, or treat user inputs as data parameters instead of executable code."
                        })
                        break
                except Exception:
                    pass

        return findings
