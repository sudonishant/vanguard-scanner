# Vanguard Scanner

Vanguard is a Python command-line web scanner that crawls same-domain HTML pages, checks selected HTTP response headers, probes discovered URL parameters and HTML forms with test payloads, and writes an interactive HTML report. It is intended for authorized security testing and learning—not as a replacement for a full authenticated or browser-based assessment.

## What it currently does

- Crawls up to a configurable number of same-domain URLs (default: 15).
- Extracts links and named form controls from server-rendered HTML with BeautifulSoup. JavaScript is not executed.
- Checks the target response for `Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options`, `Strict-Transport-Security`, and `Referrer-Policy`.
- Reports the presence of `Server`, `X-Powered-By`, and `X-AspNet-Version` response headers.
- Sends active GET and POST probes for reflected XSS, SQL error signatures, LFI, command-injection response signatures, and simple SSTI evaluation patterns. POST forms are also checked for a likely hidden CSRF-token field.
- Produces a self-contained HTML report with findings, severity counts, tested URLs, and forms.

These are response-signature checks and heuristic indicators. A finding is not proof of exploitability, and no finding is not proof that a target is secure.

## Current limitations and safety notes

- **Only scan systems you own or have explicit permission to test.** Probes can reach application endpoints and POST forms; they may create or change server-side state.
- There is no authentication/session configuration, JavaScript rendering, login workflow, rate limiting, allowlist, or crawl-delay option. It does not cover authenticated areas, client-side-only routes, or APIs unless they are exposed through discovered HTML links/forms.
- Requests use a fixed five-second timeout and disable TLS certificate verification in the scanner modules. This makes the tool unsuitable as a production-grade transport or security control and can hide certificate problems.
- The scanner submits payloads to every discovered named form field except submit/button controls. Use a disposable or staging target whenever possible, and review forms before scanning.
- Error messages and reflected values are included in the generated report. Treat reports as sensitive and do not publish them if they contain private URLs, parameters, or response-derived data.
- The current code has no automated test suite. Validate results against the target and manually review false positives and negatives.

## Quick start

### Requirements

- Python 3.8 or newer
- Git
- Network access to the authorized target

```bash
git clone https://github.com/sudonishant/vanguard-scanner.git
cd vanguard-scanner
python3 -m venv .venv

# Linux/macOS
source .venv/bin/activate

# Windows PowerShell
# .\\.venv\\Scripts\\Activate.ps1

python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

Check the installed CLI without contacting a target:

```bash
python vanguard.py --help
```

Run a scan only against an authorized target:

```bash
python vanguard.py https://example.com --depth 15 --output vanguard_report.html
```

`--depth` is the maximum number of pages the crawler visits; `--output` is the report path. The target may omit its scheme and will then default to `https://`. There are no required environment variables or configuration files.

Open the generated report with your platform's normal HTML viewer, for example:

```bash
# Linux
xdg-open vanguard_report.html
# macOS
open vanguard_report.html
# Windows PowerShell
Start-Process .\\vanguard_report.html
```

## How the scan is wired

```text
Target URL
   |
   +--> HeaderScanner      -> missing/disclosure header findings
   |
   +--> Crawler            -> same-domain URLs + HTML forms
              |
              +--> VulnerabilityScanner -> active GET/POST probes
                                           |
                                           +--> ReportGenerator -> HTML report
```

The entry point is [`vanguard.py`](./vanguard.py). Implementation is split across [`scanner/crawler.py`](./scanner/crawler.py), [`scanner/headers.py`](./scanner/headers.py), [`scanner/vulnerabilities.py`](./scanner/vulnerabilities.py), and [`scanner/reporter.py`](./scanner/reporter.py).

## CLI reference

```text
usage: vanguard.py [-h] [-o OUTPUT] [-d DEPTH] target

positional arguments:
  target                Target URL to scan (for example, https://example.com)

options:
  -h, --help            show this help message and exit
  -o OUTPUT, --output OUTPUT
                        HTML report path (default: vanguard_report.html)
  -d DEPTH, --depth DEPTH
                        Maximum number of pages to crawl (default: 15)
```

The request timeout is currently fixed in the scanner code; `--timeout` is not a supported option.

## Development checks

There is no project test suite at present. The CI workflow runs a focused flake8 syntax/name check plus a non-blocking style report. Local checks can be run with:

```bash
python3 -m py_compile vanguard.py scanner/*.py
# If flake8 is installed:
flake8 . --count --select=E9,F63,F7,F82 --show-source --statistics
```

For additional setup notes, see [`SETUP_GUIDE.md`](./SETUP_GUIDE.md). Contributions should also follow [`CONTRIBUTING.md`](./CONTRIBUTING.md).

## License

Vanguard is distributed under the [MIT License](./LICENSE).
