import os
import json
from datetime import datetime

class ReportGenerator:
    def __init__(self, target, findings, crawled_count, forms_count):
        self.target = target
        self.findings = findings
        self.crawled_count = crawled_count
        self.forms_count = forms_count
        self.timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def generate(self, output_filepath="vanguard_report.html"):
        """Generate a beautiful, premium HTML report of the findings."""
        
        # Count severities
        stats = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        for f in self.findings:
            sev = f.get("severity", "Low")
            if sev in stats:
                stats[sev] += 1

        total_issues = len(self.findings)

        # Generate findings HTML cards
        findings_html = ""
        if not self.findings:
            findings_html = """
            <div class="no-findings">
                <div class="icon">🛡️</div>
                <h3>No Vulnerabilities Found!</h3>
                <p>The scanner did not detect any security flaws. Ensure you test endpoints that process inputs for deeper checks.</p>
            </div>
            """
        else:
            for idx, f in enumerate(self.findings):
                severity_class = f.get("severity", "Low").lower()
                
                # Dynamic fields based on vulnerability type
                meta_details = ""
                if "url" in f:
                    meta_details += f'<div class="meta-item"><strong>Target URL:</strong> <code>{f["url"]}</code></div>'
                if "parameter" in f:
                    meta_details += f'<div class="meta-item"><strong>Parameter:</strong> <code>{f["parameter"]}</code></div>'
                if "method" in f:
                    meta_details += f'<div class="meta-item"><strong>HTTP Method:</strong> <span class="badge badge-method">{f["method"]}</span></div>'
                if "payload" in f:
                    # Escape payload for safe HTML display
                    escaped_payload = f["payload"].replace("<", "&lt;").replace(">", "&gt;")
                    meta_details += f'<div class="meta-item"><strong>Injected Payload:</strong> <code class="payload-box">{escaped_payload}</code></div>'

                findings_html += f"""
                <div class="card finding-card">
                    <div class="finding-header" onclick="toggleFinding('finding-{idx}')">
                        <div class="finding-title-group">
                            <span class="severity-indicator sev-{severity_class}">{f.get('severity', 'Low')}</span>
                            <h3 class="finding-title">{f.get('type', 'Security Finding')} - {f.get('name', '')}</h3>
                        </div>
                        <span class="toggle-icon" id="icon-finding-{idx}">▼</span>
                    </div>
                    <div class="finding-body collapsed" id="finding-{idx}">
                        <div class="finding-details-grid">
                            <div class="details-left">
                                <h4>Description</h4>
                                <p>{f.get('description', 'No description available.')}</p>
                                
                                <h4>Impact</h4>
                                <p>{f.get('impact', 'No impact details available.')}</p>
                                
                                <h4>Remediation</h4>
                                <p class="remediation-text">💡 {f.get('remediation', 'No remediation available.')}</p>
                            </div>
                            <div class="details-right">
                                <h4>Technical Context</h4>
                                <div class="meta-box">
                                    {meta_details}
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
                """

        html_template = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Vanguard Security Scan Report - {self.target}</title>
    <style>
        :root {{
            --bg-color: #0b0f19;
            --card-bg: #151c2c;
            --text-color: #f3f4f6;
            --text-muted: #9ca3af;
            --border-color: #1f2937;
            --primary: #6366f1;
            --primary-hover: #4f46e5;
            
            --critical: #ef4444;
            --high: #f97316;
            --medium: #eab308;
            --low: #3b82f6;
            
            --critical-bg: rgba(239, 68, 68, 0.1);
            --high-bg: rgba(249, 115, 22, 0.1);
            --medium-bg: rgba(234, 179, 8, 0.1);
            --low-bg: rgba(59, 130, 246, 0.1);
        }}

        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
        }}

        body {{
            background-color: var(--bg-color);
            color: var(--text-color);
            padding: 2rem 1rem;
            line-height: 1.6;
        }}

        .container {{
            max-width: 1100px;
            margin: 0 auto;
        }}

        /* Header styles */
        header {{
            background: linear-gradient(135deg, #1e1b4b 0%, #0f172a 100%);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 2rem;
            margin-bottom: 2rem;
            box-shadow: 0 4px 20px rgba(0, 0, 0, 0.3);
            position: relative;
            overflow: hidden;
        }}

        header::before {{
            content: '';
            position: absolute;
            top: -50%;
            right: -20%;
            width: 300px;
            height: 300px;
            background: radial-gradient(circle, rgba(99, 102, 241, 0.15) 0%, transparent 70%);
            border-radius: 50%;
        }}

        .header-title-group {{
            display: flex;
            align-items: center;
            gap: 12px;
            margin-bottom: 1rem;
        }}

        .logo {{
            font-size: 2rem;
            background: linear-gradient(to right, #818cf8, #c084fc);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            font-weight: 800;
            letter-spacing: -1px;
        }}

        .scan-target-text {{
            font-size: 1.1rem;
            color: var(--text-muted);
        }}

        .scan-target-text code {{
            background-color: rgba(255, 255, 255, 0.08);
            padding: 3px 8px;
            border-radius: 4px;
            font-family: monospace;
            color: #818cf8;
            font-size: 0.95rem;
        }}

        .meta-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1.5rem;
            margin-top: 1.5rem;
            border-top: 1px dashed var(--border-color);
            padding-top: 1.5rem;
        }}

        .meta-card {{
            display: flex;
            flex-direction: column;
        }}

        .meta-card h5 {{
            color: var(--text-muted);
            text-transform: uppercase;
            font-size: 0.75rem;
            letter-spacing: 1px;
            margin-bottom: 4px;
        }}

        .meta-card p {{
            font-size: 1.1rem;
            font-weight: 600;
        }}

        /* Dashboard Statistics */
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 1rem;
            margin-bottom: 2rem;
        }}

        @media (max-width: 768px) {{
            .stats-grid {{
                grid-template-columns: repeat(2, 1fr);
            }}
        }}

        .stat-card {{
            background-color: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 1.5rem;
            text-align: center;
            position: relative;
        }}

        .stat-card.critical {{ border-top: 4px solid var(--critical); }}
        .stat-card.high {{ border-top: 4px solid var(--high); }}
        .stat-card.medium {{ border-top: 4px solid var(--medium); }}
        .stat-card.low {{ border-top: 4px solid var(--low); }}

        .stat-num {{
            font-size: 2.2rem;
            font-weight: 800;
            line-height: 1.2;
            margin-bottom: 4px;
        }}

        .critical .stat-num {{ color: var(--critical); }}
        .high .stat-num {{ color: var(--high); }}
        .medium .stat-num {{ color: var(--medium); }}
        .low .stat-num {{ color: var(--low); }}

        .stat-label {{
            font-size: 0.8rem;
            color: var(--text-muted);
            text-transform: uppercase;
            font-weight: 600;
            letter-spacing: 0.5px;
        }}

        /* Findings Area */
        .section-title {{
            font-size: 1.5rem;
            font-weight: 700;
            margin-bottom: 1.5rem;
            display: flex;
            align-items: center;
            gap: 10px;
        }}

        .card {{
            background-color: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            margin-bottom: 1rem;
            overflow: hidden;
            transition: all 0.2s ease;
        }}

        .finding-card:hover {{
            box-shadow: 0 4px 15px rgba(0, 0, 0, 0.4);
            border-color: #374151;
        }}

        .finding-header {{
            padding: 1.25rem 1.5rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
            cursor: pointer;
            user-select: none;
        }}

        .finding-title-group {{
            display: flex;
            align-items: center;
            gap: 12px;
        }}

        .severity-indicator {{
            font-size: 0.75rem;
            font-weight: 700;
            text-transform: uppercase;
            padding: 4px 8px;
            border-radius: 4px;
            letter-spacing: 0.5px;
            min-width: 80px;
            text-align: center;
        }}

        .sev-critical {{ background-color: var(--critical-bg); color: var(--critical); border: 1px solid var(--critical); }}
        .sev-high {{ background-color: var(--high-bg); color: var(--high); border: 1px solid var(--high); }}
        .sev-medium {{ background-color: var(--medium-bg); color: var(--medium); border: 1px solid var(--medium); }}
        .sev-low {{ background-color: var(--low-bg); color: var(--low); border: 1px solid var(--low); }}

        .finding-title {{
            font-size: 1.05rem;
            font-weight: 600;
        }}

        .toggle-icon {{
            color: var(--text-muted);
            font-size: 0.8rem;
            transition: transform 0.2s ease;
        }}

        .finding-body {{
            padding: 0 1.5rem 1.5rem 1.5rem;
            border-top: 1px solid var(--border-color);
            background-color: rgba(0, 0, 0, 0.15);
            transition: max-height 0.3s ease-out;
        }}

        .finding-body.collapsed {{
            display: none;
        }}

        .finding-details-grid {{
            display: grid;
            grid-template-columns: 3fr 2fr;
            gap: 1.5rem;
            margin-top: 1.5rem;
        }}

        @media (max-width: 768px) {{
            .finding-details-grid {{
                grid-template-columns: 1fr;
            }}
        }}

        .finding-details-grid h4 {{
            font-size: 0.9rem;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            color: var(--primary);
            margin-bottom: 8px;
            margin-top: 12px;
        }}

        .finding-details-grid h4:first-child {{
            margin-top: 0;
        }}

        .finding-details-grid p {{
            color: #d1d5db;
            margin-bottom: 12px;
            font-size: 0.95rem;
        }}

        .remediation-text {{
            background-color: rgba(99, 102, 241, 0.05);
            border-left: 3px solid var(--primary);
            padding: 10px 12px;
            border-radius: 0 4px 4px 0;
        }}

        .meta-box {{
            background-color: rgba(0, 0, 0, 0.3);
            border: 1px solid var(--border-color);
            border-radius: 6px;
            padding: 1rem;
        }}

        .meta-item {{
            margin-bottom: 10px;
            font-size: 0.85rem;
        }}

        .meta-item:last-child {{
            margin-bottom: 0;
        }}

        .meta-item code {{
            background-color: rgba(255, 255, 255, 0.08);
            padding: 2px 6px;
            border-radius: 3px;
            word-break: break-all;
            color: #f3f4f6;
            font-family: monospace;
        }}

        .payload-box {{
            display: block;
            margin-top: 5px;
            padding: 8px !important;
            border: 1px solid var(--border-color);
            background-color: #0b0f19 !important;
            color: #38bdf8 !important;
        }}

        .badge-method {{
            background-color: var(--primary);
            color: white;
            padding: 2px 6px;
            border-radius: 4px;
            font-weight: 700;
        }}

        .no-findings {{
            text-align: center;
            padding: 4rem 2rem;
            background-color: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 8px;
        }}

        .no-findings .icon {{
            font-size: 3.5rem;
            margin-bottom: 1rem;
        }}

        .no-findings h3 {{
            font-size: 1.3rem;
            margin-bottom: 8px;
        }}

        .no-findings p {{
            color: var(--text-muted);
            max-width: 500px;
            margin: 0 auto;
        }}

        footer {{
            text-align: center;
            margin-top: 3rem;
            color: var(--text-muted);
            font-size: 0.8rem;
            border-top: 1px solid var(--border-color);
            padding-top: 1.5rem;
        }}
    </style>
    <script>
        function toggleFinding(id) {{
            const el = document.getElementById(id);
            const icon = document.getElementById('icon-' + id);
            if (el.classList.contains('collapsed')) {{
                el.classList.remove('collapsed');
                icon.style.transform = 'rotate(180deg)';
            }} else {{
                el.classList.add('collapsed');
                icon.style.transform = 'rotate(0deg)';
            }}
        }}
    </script>
</head>
<body>
    <div class="container">
        <header>
            <div class="header-title-group">
                <span class="logo">VANGUARD</span>
                <span style="font-weight: 300; color: var(--text-muted)">| Vulnerability Report</span>
            </div>
            <div class="scan-target-text">
                Target URL: <code>{self.target}</code>
            </div>
            <div class="meta-grid">
                <div class="meta-card">
                    <h5>Scan Date</h5>
                    <p>{self.timestamp}</p>
                </div>
                <div class="meta-card">
                    <h5>Pages Crawled</h5>
                    <p>{self.crawled_count}</p>
                </div>
                <div class="meta-card">
                    <h5>Forms Analyzed</h5>
                    <p>{self.forms_count}</p>
                </div>
                <div class="meta-card">
                    <h5>Total Vulnerabilities</h5>
                    <p style="color: {'var(--critical)' if total_issues > 0 else 'var(--text-color)'}">{total_issues}</p>
                </div>
            </div>
        </header>

        <div class="stats-grid">
            <div class="stat-card critical">
                <div class="stat-num">{stats['Critical']}</div>
                <div class="stat-label">Critical</div>
            </div>
            <div class="stat-card high">
                <div class="stat-num">{stats['High']}</div>
                <div class="stat-label">High</div>
            </div>
            <div class="stat-card medium">
                <div class="stat-num">{stats['Medium']}</div>
                <div class="stat-label">Medium</div>
            </div>
            <div class="stat-card low">
                <div class="stat-num">{stats['Low']}</div>
                <div class="stat-label">Low</div>
            </div>
        </div>

        <main>
            <h2 class="section-title">🛡️ Security Vulnerabilities ({total_issues})</h2>
            {findings_html}
        </main>

        <footer>
            <p>Generated by Vanguard Vulnerability Scanner. Designed for ethical security assessment.</p>
        </footer>
    </div>
</body>
</html>
        """

        try:
            with open(output_filepath, "w", encoding="utf-8") as f:
                f.write(html_template)
            return os.path.abspath(output_filepath)
        except Exception as e:
            return None
