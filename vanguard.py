#!/usr/bin/env python3
import sys
import argparse
from urllib.parse import urlparse
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.markdown import Markdown
from rich.progress import Progress, SpinnerColumn, TextColumn

# Import our scanner modules
from scanner.crawler import Crawler
from scanner.headers import HeaderScanner
from scanner.vulnerabilities import VulnerabilityScanner
from scanner.reporter import ReportGenerator

# Initialize Rich Console for beautiful terminal outputs
console = Console()

BANNER = """
[bold purple]
██╗   ██╗ █████╗ ███╗   ██╗ ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗ 
██║   ██║██╔══██╗████╗  ██║██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗
██║   ██║███████║██╔██╗ ██║██║  ███╗██║   ██║███████║██████╔╝██║  ██║
╚██╗ ██╔╝██╔══██║██║╚██╗██║██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║
 ╚████╔╝ ██║  ██║██║ ╚████║╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝
  ╚═══╝  ╚═╝  ╚═╝╚═╝  ╚═══╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ 
[/bold purple]
                 [bold cyan]Vanguard - Premium Security Scanner v1.0.0[/bold cyan]
                [dim]Developed by Nishant Kumar (Neeshant01)[/dim]
"""

def validate_url(url):
    """Ensure the URL has a valid scheme and netloc."""
    try:
        parsed = urlparse(url)
        return bool(parsed.scheme and parsed.netloc)
    except Exception:
        return False

def main():
    console.print(BANNER)
    
    # Set up argument parser
    parser = argparse.ArgumentParser(description="Vanguard - Vulnerability & Security Scanner")
    parser.add_argument("target", help="Target URL to scan (e.g., https://example.com)")
    parser.add_argument("-o", "--output", default="vanguard_report.html", help="Path to save the HTML report (default: vanguard_report.html)")
    parser.add_argument("-d", "--depth", type=int, default=15, help="Maximum number of pages to crawl (default: 15)")
    
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    args = parser.parse_args()
    target_url = args.target

    # Validate target URL
    if not target_url.startswith(("http://", "https://")):
        target_url = "https://" + target_url

    if not validate_url(target_url):
        console.print(f"[bold red]Error:[/bold red] The URL '{args.target}' is invalid. Please include scheme (e.g. http:// or https://).")
        sys.exit(1)

    console.print(Panel(f"[bold green]Starting Security Audit[/bold green]\n[bold]Target:[/bold] {target_url}\n[bold]Max Crawl Depth:[/bold] {args.depth} pages\n[bold]Report Output:[/bold] {args.output}", border_style="purple"))

    findings = []
    crawled_urls = [target_url]
    forms = []

    try:
        # Step 1: Scan HTTP Security Headers
        with console.status("[bold cyan]Analyzing HTTP security headers...", spinner="dots") as status:
            header_scanner = HeaderScanner(target_url)
            header_findings = header_scanner.analyze()
            findings.extend(header_findings)
            console.print("[green]✔[/green] HTTP Security Header check completed.")

        # Step 2: Crawl Website for Links and Forms
        with console.status("[bold cyan]Crawling website & discovering forms...", spinner="dots") as status:
            crawler = Crawler(target_url, max_pages=args.depth)
            crawled_urls, forms = crawler.crawl()
            console.print(f"[green]✔[/green] Crawling finished. Visited [bold]{len(crawled_urls)}[/bold] URLs and found [bold]{len(forms)}[/bold] forms.")

        # Step 3: Test Vulnerabilities
        vuln_scanner = VulnerabilityScanner()
        
        # We use Progress bar for active scanning
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            
            # Sub-task 1: Scan parameters on crawled pages
            param_task = progress.add_task(description="Scanning URL query parameters for XSS/SQLi...", total=len(crawled_urls))
            for url in crawled_urls:
                param_findings = vuln_scanner.test_url_parameters(url)
                findings.extend(param_findings)
                progress.advance(param_task)

            # Sub-task 2: Scan discovered forms
            if forms:
                form_task = progress.add_task(description="Testing input forms for XSS/SQLi...", total=len(forms))
                for form in forms:
                    form_findings = vuln_scanner.test_form(form)
                    findings.extend(form_findings)
                    progress.advance(form_task)
            
            console.print("[green]✔[/green] Vulnerability scanning completed.")

        # Step 4: Generate Reports
        with console.status("[bold cyan]Compiling and generating HTML report...", spinner="dots") as status:
            reporter = ReportGenerator(target_url, findings, len(crawled_urls), len(forms))
            report_path = reporter.generate(args.output)
            
        console.print(Panel(f"[bold green]✔ Scan Completed Successfully![/bold green]\n\n[bold]Report Saved To:[/bold] [underline cyan]{report_path}[/underline cyan]", border_style="green"))

        # Step 5: Summary Table in Terminal
        if findings:
            table = Table(title="Vanguard Scan Summary Findings", header_style="bold magenta", border_style="purple")
            table.add_column("Vulnerability Type", justify="left")
            table.add_column("Severity", justify="center")
            table.add_column("Details", justify="left")

            for f in findings:
                sev = f.get("severity", "Low")
                if sev == "Critical":
                    sev_str = f"[bold red]{sev}[/bold red]"
                elif sev == "High":
                    sev_str = f"[bold orange3]{sev}[/bold orange3]"
                elif sev == "Medium":
                    sev_str = f"[bold yellow]{sev}[/bold yellow]"
                else:
                    sev_str = f"[bold blue]{sev}[/bold blue]"
                
                table.add_row(f.get("type", ""), sev_str, f.get("name", ""))

            console.print(table)
        else:
            console.print("\n[bold green]No vulnerabilities detected! Great job, target seems secure.[/bold green]\n")

    except KeyboardInterrupt:
        console.print("\n[bold red]Scan aborted by user.[/bold red]")
        sys.exit(0)
    except Exception as e:
        console.print(f"\n[bold red]An unexpected error occurred during the scan:[/bold red] {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()
