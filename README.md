# Vanguard: Automated Web Vulnerability Scanner & Recon Tool 🛡️

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)
[![Cybersecurity Tool](https://img.shields.io/badge/Cybersecurity-Ethical--Hacking-purple.svg)]()

**Vanguard** is a premium, modular command-line vulnerability scanner designed for ethical hackers, security analysts, and developers. It crawls target websites, evaluates HTTP response security headers, and tests endpoints/forms for critical vulnerabilities such as **Cross-Site Scripting (XSS)** and **SQL Injection (SQLi)**. It then compiles the results into a stunning, responsive, dark-mode **HTML report** for audit documentation.

---

## ✨ Features

- **🌐 Target Crawling & Mapping**: Recursively crawls domains up to a configurable depth to discover hidden endpoints, URLs, and active HTML forms.
- **🔒 Security Header Audit**: Evaluates HTTP response headers for missing configurations (`CSP`, `X-Frame-Options`, `HSTS`, `X-Content-Type-Options`) and flags dangerous information disclosures (e.g. `Server` or `X-Powered-By`).
- **⚔️ Active Vulnerability Probing**:
  - **Cross-Site Scripting (XSS)**: Performs active injection in query parameters and forms to check for reflections and lack of HTML escaping.
  - **SQL Injection (SQLi)**: Injects SQL syntax payloads and monitors server responses for common database driver error signatures.
- **🎨 Stunning CLI Dashboard**: Features real-time scanning loaders, tables, and color-coded severities utilizing the `rich` library.
- **📄 Premium HTML Report**: Generates an interactive, modern, CSS-styled HTML report featuring statistics, interactive accordions, and detailed remediation advice for every vulnerability found.

---

## 🛠️ Architecture

```mermaid
graph TD
    A[vanguard.py - CLI Entry] --> B[Crawler - URL/Form Finder]
    A --> C[HeaderScanner - HTTP Security Evaluator]
    A --> D[VulnerabilityScanner - XSS & SQLi Prober]
    B --> E[Found Targets & Forms]
    E --> D
    D --> F[Audit Findings List]
    C --> F
    F --> G[ReportGenerator - Interactive HTML Audit Report]
    F --> H[Rich CLI Terminal Summary Table]
```

---

## 🚀 Installation

### 1. Clone the Repository
```bash
git clone https://github.com/Neeshant01/vanguard-scanner.git
cd vanguard-scanner
```

### 2. Set Up a Virtual Environment (Recommended)
```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

---

## 💻 Usage

To run a default scan on a target website:
```bash
python vanguard.py https://example.com
```

### Advanced Flags:
| Flag | Long Flag | Description | Default |
| :--- | :--- | :--- | :--- |
| `-h` | `--help` | Show help menu and options | - |
| `-o` | `--output` | Customize the filepath of the generated HTML report | `vanguard_report.html` |
| `-d` | `--depth` | Maximum number of URLs to crawl and audit | `15` |

### Scanning Example:
```bash
python vanguard.py testphp.vulnweb.com -o audit_report.html -d 20
```

---

## 📊 Vulnerability Check Index

| Check Name | Severity | Type |
| :--- | :---: | :---: |
| **SQL Injection (SQLi)** | `Critical` | Active Probe |
| **Cross-Site Scripting (XSS)** | `High` | Active Probe |
| **Missing Content-Security-Policy (CSP)** | `Medium` | Passive Audit |
| **Missing X-Frame-Options (Clickjacking)** | `Medium` | Passive Audit |
| **Missing Strict-Transport-Security (HSTS)** | `Medium` | Passive Audit |
| **Missing X-Content-Type-Options** | `Low` | Passive Audit |
| **Server Version / Powered-By Disclosure** | `Low` | Passive Audit |

---

## 📝 Disclaimer

> [!WARNING]
> This tool is developed strictly for **educational purposes** and **authorized security assessments (penetration testing)**. Running Vanguard against targets without explicit, written consent is illegal and a violation of computer misuse acts. The developer assumes no liability for misuse or damage caused by this program.

---

## 📄 License

Distributed under the MIT License. See `LICENSE` for more information.
