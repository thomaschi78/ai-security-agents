"""HTML report writer using Jinja2 templates."""

from pathlib import Path
from typing import Any, Dict, Optional
from datetime import datetime

try:
    from jinja2 import Environment, FileSystemLoader, select_autoescape
    JINJA2_AVAILABLE = True
except ImportError:
    JINJA2_AVAILABLE = False

from ..results import ScanResult, Severity


# Inline template for when template file not found
DEFAULT_HTML_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Scan Report - {{ scan.id[:8] }}</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; line-height: 1.6; color: #333; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
        header { background: #1a1a2e; color: white; padding: 30px 0; margin-bottom: 30px; }
        header h1 { text-align: center; }
        .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 30px; }
        .card { background: white; border-radius: 8px; padding: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .card h3 { margin-bottom: 10px; color: #666; font-size: 0.9em; text-transform: uppercase; }
        .card .value { font-size: 2em; font-weight: bold; }
        .critical { color: #d32f2f; }
        .high { color: #f57c00; }
        .medium { color: #fbc02d; }
        .low { color: #388e3c; }
        .findings { margin-top: 30px; }
        .finding { background: white; border-radius: 8px; margin-bottom: 20px; overflow: hidden; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .finding-header { padding: 15px 20px; display: flex; justify-content: space-between; align-items: center; }
        .finding-header.critical { background: #ffebee; border-left: 4px solid #d32f2f; }
        .finding-header.high { background: #fff3e0; border-left: 4px solid #f57c00; }
        .finding-header.medium { background: #fffde7; border-left: 4px solid #fbc02d; }
        .finding-header.low { background: #e8f5e9; border-left: 4px solid #388e3c; }
        .finding-body { padding: 20px; border-top: 1px solid #eee; }
        .badge { padding: 4px 12px; border-radius: 20px; font-size: 0.8em; font-weight: bold; text-transform: uppercase; }
        .badge.critical { background: #d32f2f; color: white; }
        .badge.high { background: #f57c00; color: white; }
        .badge.medium { background: #fbc02d; color: #333; }
        .badge.low { background: #388e3c; color: white; }
        .detail-grid { display: grid; grid-template-columns: repeat(2, 1fr); gap: 15px; margin-bottom: 15px; }
        .detail-item label { display: block; font-size: 0.8em; color: #666; margin-bottom: 4px; }
        .detail-item code { background: #f5f5f5; padding: 4px 8px; border-radius: 4px; font-size: 0.9em; }
        pre { background: #1a1a2e; color: #fff; padding: 15px; border-radius: 4px; overflow-x: auto; margin-top: 10px; }
        .remediation { background: #e3f2fd; padding: 15px; border-radius: 4px; margin-top: 15px; }
        .remediation h4 { color: #1565c0; margin-bottom: 8px; }
        footer { text-align: center; padding: 30px; color: #666; font-size: 0.9em; }
    </style>
</head>
<body>
    <header>
        <div class="container">
            <h1>🔒 Security Scan Report</h1>
            <p style="text-align:center; opacity:0.8; margin-top:10px;">
                Generated: {{ generated_at }} | Target: {{ scan.target.url if scan.target else 'N/A' }}
            </p>
        </div>
    </header>

    <div class="container">
        <div class="summary">
            <div class="card">
                <h3>Total Findings</h3>
                <div class="value">{{ summary.total_findings }}</div>
            </div>
            <div class="card">
                <h3>Critical</h3>
                <div class="value critical">{{ summary.critical }}</div>
            </div>
            <div class="card">
                <h3>High</h3>
                <div class="value high">{{ summary.high }}</div>
            </div>
            <div class="card">
                <h3>Medium</h3>
                <div class="value medium">{{ summary.medium }}</div>
            </div>
            <div class="card">
                <h3>Low</h3>
                <div class="value low">{{ summary.low }}</div>
            </div>
            <div class="card">
                <h3>Duration</h3>
                <div class="value" style="font-size:1.5em;">{{ summary.duration }}</div>
            </div>
        </div>

        <div class="findings">
            <h2 style="margin-bottom: 20px;">Vulnerability Details</h2>
            {% for vuln in vulnerabilities %}
            <div class="finding">
                <div class="finding-header {{ vuln.severity }}">
                    <div>
                        <strong>{{ vuln.vulnerability_type|upper }}</strong> - CWE-{{ vuln.cweid }}
                    </div>
                    <span class="badge {{ vuln.severity }}">{{ vuln.severity|upper }}</span>
                </div>
                <div class="finding-body">
                    <div class="detail-grid">
                        <div class="detail-item">
                            <label>URL</label>
                            <code>{{ vuln.url }}</code>
                        </div>
                        <div class="detail-item">
                            <label>Parameter</label>
                            <code>{{ vuln.parameter }}</code>
                        </div>
                        <div class="detail-item">
                            <label>Confidence</label>
                            <code>{{ "%.0f"|format(vuln.confidence_score * 100) }}%</code>
                        </div>
                        <div class="detail-item">
                            <label>OWASP Category</label>
                            <code>{{ vuln.owasp_category }}</code>
                        </div>
                    </div>

                    {% if vuln.payload %}
                    <div class="detail-item">
                        <label>Payload</label>
                        <pre>{{ vuln.payload }}</pre>
                    </div>
                    {% endif %}

                    {% if vuln.indicators %}
                    <div class="detail-item" style="margin-top:15px;">
                        <label>Detection Indicators</label>
                        <ul style="margin-left:20px; margin-top:5px;">
                        {% for indicator in vuln.indicators[:5] %}
                            <li>{{ indicator }}</li>
                        {% endfor %}
                        </ul>
                    </div>
                    {% endif %}

                    <div class="remediation">
                        <h4>Remediation</h4>
                        <p>{{ vuln.get_remediation() }}</p>
                    </div>
                </div>
            </div>
            {% else %}
            <div class="card" style="text-align:center; padding:40px;">
                <p style="color:#388e3c; font-size:1.2em;">✅ No vulnerabilities found</p>
            </div>
            {% endfor %}
        </div>
    </div>

    <footer>
        <p>Generated by AI Security Agents Framework | <a href="{{ cwe_base_url }}">CWE Reference</a></p>
    </footer>
</body>
</html>
'''


class HTMLWriter:
    """Writes scan results to HTML format."""

    def __init__(
        self,
        template_dir: Optional[str] = None,
        template_name: str = "report.html.jinja2"
    ):
        self.template_dir = template_dir
        self.template_name = template_name

        if not JINJA2_AVAILABLE:
            raise ImportError("jinja2 package required for HTML reports")

    def write(self, result: ScanResult, output_path: str) -> str:
        """
        Write scan result to HTML file.

        Args:
            result: Scan result to write
            output_path: Output file path

        Returns:
            Path to written file
        """
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)

        html = self._render(result)

        with open(path, "w") as f:
            f.write(html)

        return str(path)

    def _render(self, result: ScanResult) -> str:
        """Render HTML report."""
        # Try to load template from file, fall back to default
        try:
            if self.template_dir:
                env = Environment(
                    loader=FileSystemLoader(self.template_dir),
                    autoescape=select_autoescape(['html', 'xml'])
                )
                template = env.get_template(self.template_name)
            else:
                raise FileNotFoundError("No template directory specified")
        except Exception:
            # Use inline default template
            env = Environment(autoescape=select_autoescape(['html', 'xml']))
            template = env.from_string(DEFAULT_HTML_TEMPLATE)

        # Prepare template data
        data = {
            "scan": result,
            "summary": result.get_summary(),
            "vulnerabilities": result.vulnerabilities,
            "generated_at": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
            "cwe_base_url": "https://cwe.mitre.org/data/definitions/",
        }

        return template.render(**data)

    def to_string(self, result: ScanResult) -> str:
        """Render scan result to HTML string."""
        return self._render(result)
