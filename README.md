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

## 📥 Detailed Download & Installation Guide

### Prerequisites
Before installing Vanguard, ensure your system has Python 3.8+ and `git` installed.

#### On Linux (Ubuntu / Debian / Kali Linux):
```bash
sudo apt update
sudo apt install -y python3 python3-pip python3-venv git
```

#### On macOS:
```bash
brew install python git
```

---

### Option 1: Downloading via Git (Recommended)

Open your terminal and execute the following commands step-by-step:

```bash
# 1. Clone the GitHub repository
git clone https://github.com/sudonishant/vanguard-scanner.git

# 2. Navigate into the project directory
cd vanguard-scanner
```

---

### Option 2: Manual Download (ZIP Archive)

If you don't have `git` installed:
1. Download the ZIP file directly: [vanguard-scanner main.zip](https://github.com/sudonishant/vanguard-scanner/archive/refs/heads/main.zip)
2. Extract the archive and open your terminal inside the extracted `vanguard-scanner-main` directory:
```bash
cd path/to/vanguard-scanner-main
```

---

## ⚙️ Environment Setup & Dependency Installation

To prevent dependency conflicts with your system's global Python environment (avoiding `externally-managed-environment` errors), set up a virtual environment:

### Step 1: Create a Virtual Environment

```bash
python3 -m venv venv
```

### Step 2: Activate the Virtual Environment

- **Linux / macOS (Bash/Zsh):**
  ```bash
  source venv/bin/activate
  ```
- **Windows (PowerShell):**
  ```powershell
  .\venv\Scripts\Activate.ps1
  ```
- **Windows (Command Prompt):**
  ```cmd
  venv\Scripts\activate.bat
  ```

*(Once activated, your terminal prompt will show `(venv)` at the beginning).*

### Step 3: Upgrade Pip & Install Dependencies

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

---

## 💻 How to Run Vanguard Scanner

### 1. Verify Installation
Check that the scanner CLI is ready by printing the help menu:
```bash
python vanguard.py --help
```

### 2. Run a Vulnerability Audit
Execute a scan against your target URL and export an interactive HTML report:
```bash
python vanguard.py https://example.com -o audit_report.html
```

### 3. Open & View the Report
Once completed, open the generated `audit_report.html` file in your preferred web browser:
- **Linux:** `xdg-open audit_report.html`
- **macOS:** `open audit_report.html`
- **Windows:** `start audit_report.html`

---

## ⚙️ CLI Reference & Flags

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

## 📖 Extended Troubleshooting & Setup Notes
For advanced debugging (such as fixing BeautifulSoup parsing limits or network timeouts), read the full [SETUP_GUIDE.md](./SETUP_GUIDE.md).

---

## ⚖️ Legal & Ethical Disclaimer
> [!IMPORTANT]
> **Vanguard** is strictly designed for legal, ethical security assessments and educational purposes. Scanning targets without explicit prior written authorization from the owner is illegal and violates security policies. The developer assumes no liability for unauthorized usage.

---

## 📜 License
Distributed under the MIT License. See [LICENSE](./LICENSE) for details.
