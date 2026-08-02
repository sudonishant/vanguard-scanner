# Vanguard: Automated Web Vulnerability Scanner & Reconnaissance Engine 🛡️

[![Python Version](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)
[![Cybersecurity Tool](https://img.shields.io/badge/Cybersecurity-Ethical--Hacking-purple.svg)]()
[![Platform Support](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows-blue.svg)]()

**Vanguard** is an enterprise-grade, modular command-line web application security scanner designed for ethical hackers, penetration testers, and security engineers. It autonomously crawls target domains, performs comprehensive HTTP security header audits, and executes multi-vector vulnerability checks—including Cross-Site Scripting (Reflected XSS), SQL Injection (SQLi), Local File Inclusion (LFI), OS Command Injection, Server-Side Template Injection (SSTI), and missing Anti-CSRF protections—generating an interactive, responsive HTML vulnerability report.

---

## 📸 Report Dashboard Preview

![Vanguard Dashboard Preview](./assets/vanguard_dashboard.png)

---

## ✨ Key Features & Capabilities

- **🌐 Autonomous Target Crawling:** Recursively crawls web domains up to configurable depths, extracting internal endpoints, query parameters, and HTML forms.
- **🔒 HTTP Security Header Audit:** Inspects HTTP response headers for missing security controls (`Content-Security-Policy`, `Strict-Transport-Security`, `X-Frame-Options`, `X-Content-Type-Options`) and identifies dangerous server technology version disclosures.
- **⚔️ Multi-Vector Vulnerability Detection:**
  - **Cross-Site Scripting (XSS):** Parameter and form injection payloads with DOM reflection verification.
  - **SQL Injection (SQLi):** Multi-database driver error signature checks (MySQL, PostgreSQL, SQLite, MSSQL).
  - **Local File Inclusion (LFI):** Traversal payloads auditing direct file read exposures (`/etc/passwd`, `win.ini`).
  - **OS Command Injection:** Shell operator auditing for arbitrary system code execution vectors.
  - **Server-Side Template Injection (SSTI):** Dynamic template evaluation checks (Jinja2, Twig, Smarty).
  - **Cross-Site Request Forgery (CSRF):** Automated inspection of state-changing forms for missing anti-CSRF token parameters.
- **📄 Interactive HTML Reporting:** Exports structured, styled HTML audit reports featuring CVSS risk scores, vulnerable URL endpoints, exact payload triggers, and remediation guidance.

---

## 🎯 Vulnerability Audit Scope

| Vulnerability Class | OWASP Top 10 Mapping | Detection Mechanism |
|---|---|---|
| **SQL Injection (SQLi)** | A03:2021 - Injection | Syntax injection & database error signature monitoring |
| **Reflected XSS** | A03:2021 - Injection | Reflection verification of unescaped HTML/JS payloads |
| **Local File Inclusion (LFI)** | A01:2021 - Broken Access Control | Path traversal checks for sensitive system file disclosures |
| **OS Command Injection** | A03:2021 - Injection | Command operator execution testing in parameter inputs |
| **SSTI** | A03:2021 - Injection | Evaluation testing of template expression syntax |
| **CSRF Safeguards** | A01:2021 - Broken Access Control | Anti-CSRF token verification on state-changing HTML forms |
| **Security Headers** | A05:2021 - Security Misconfiguration | Verification of missing defensive HTTP headers & version leaks |

---

## 🚀 Installation & Setup

### Prerequisites
- Python 3.8 or higher
- Git

### Step 1: Clone the Repository
```bash
git clone https://github.com/sudonishant/vanguard-scanner.git
cd vanguard-scanner
```

### Step 2: Create a Virtual Environment
```bash
python3 -m venv venv
source venv/bin/activate  # On Windows use: venv\Scripts\activate
```

### Step 3: Install Dependencies
```bash
pip install -r requirements.txt
```

---

## 💻 Usage & CLI Reference

### Basic Usage Command
Run a full scan against a target URL and export an interactive HTML report:
```bash
python vanguard.py https://example.com -o audit_report.html
```

### Command-Line Arguments
```text
positional arguments:
  target                Target URL to audit (e.g. https://example.com)

options:
  -h, --help            Show help message and exit
  -o OUTPUT, --output OUTPUT
                        Output HTML audit report path (default: vulnerability_report.html)
  -d DEPTH, --depth DEPTH
                        Maximum link crawl depth (default: 2)
  --timeout TIMEOUT     HTTP request timeout in seconds (default: 5)
```

---

## 📖 Extended Documentation
For comprehensive setup instructions, configuration details, and troubleshooting notes, consult the [SETUP_GUIDE.md](./SETUP_GUIDE.md).

---

## ⚖️ Legal & Ethical Disclaimer
> [!IMPORTANT]
> **Vanguard** is strictly designed for legal, ethical security assessments and educational purposes. Scanning targets without explicit prior written authorization from the owner is illegal and violates security policies. The developer assumes no liability for unauthorized usage.

---

## 📜 License
Distributed under the MIT License. See [LICENSE](./LICENSE) for details.
