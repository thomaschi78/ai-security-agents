"""Markdown report writer."""

from pathlib import Path
from typing import Optional
from datetime import datetime

from ..results import ScanResult, Severity


class MarkdownWriter:
    """Writes scan results to Markdown format."""

    def __init__(self, include_toc: bool = True, include_evidence: bool = True):
        self.include_toc = include_toc
        self.include_evidence = include_evidence

    def write(self, result: ScanResult, output_path: str) -> str:
        """
        Write scan result to Markdown file.

        Args:
            result: Scan result to write
            output_path: Output file path

        Returns:
            Path to written file
        """
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)

        md = self._render(result)

        with open(path, "w") as f:
            f.write(md)

        return str(path)

    def _render(self, result: ScanResult) -> str:
        """Render Markdown report."""
        lines = []
        summary = result.get_summary()

        # Header
        lines.append("# Security Scan Report")
        lines.append("")
        lines.append(f"**Generated:** {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}")
        lines.append(f"**Target:** {result.target.url if result.target else 'N/A'}")
        lines.append(f"**Scan ID:** `{result.id[:8]}`")
        lines.append("")

        # Table of Contents
        if self.include_toc and result.vulnerabilities:
            lines.append("## Table of Contents")
            lines.append("")
            lines.append("- [Summary](#summary)")
            lines.append("- [Findings](#findings)")
            for i, vuln in enumerate(result.vulnerabilities, 1):
                anchor = f"finding-{i}-{vuln.vulnerability_type}"
                lines.append(f"  - [{vuln.vulnerability_type.upper()} - {vuln.parameter}](#{anchor})")
            lines.append("- [Recommendations](#recommendations)")
            lines.append("")

        # Summary
        lines.append("## Summary")
        lines.append("")
        lines.append("| Metric | Value |")
        lines.append("|--------|-------|")
        lines.append(f"| Total Findings | {summary['total_findings']} |")
        lines.append(f"| Critical | {summary['critical']} |")
        lines.append(f"| High | {summary['high']} |")
        lines.append(f"| Medium | {summary['medium']} |")
        lines.append(f"| Low | {summary['low']} |")
        lines.append(f"| Duration | {summary['duration']} |")
        lines.append(f"| Payloads Tested | {summary['payloads_tested']} |")
        lines.append("")

        # Findings
        lines.append("## Findings")
        lines.append("")

        if not result.vulnerabilities:
            lines.append("✅ **No vulnerabilities found**")
            lines.append("")
        else:
            for i, vuln in enumerate(result.vulnerabilities, 1):
                severity_emoji = self._severity_emoji(vuln.severity)
                anchor = f"finding-{i}-{vuln.vulnerability_type}"

                lines.append(f"### {severity_emoji} Finding {i}: {vuln.vulnerability_type.upper()}")
                lines.append(f"<a id=\"{anchor}\"></a>")
                lines.append("")
                lines.append(f"**Severity:** {vuln.severity.value.upper()}")
                lines.append(f"**CWE:** [{vuln.cweid}]({vuln.cwe_url})")
                lines.append(f"**Confidence:** {vuln.confidence_score * 100:.0f}%")
                lines.append("")
                lines.append("| Property | Value |")
                lines.append("|----------|-------|")
                lines.append(f"| URL | `{vuln.url}` |")
                lines.append(f"| Parameter | `{vuln.parameter}` |")
                lines.append(f"| Method | {vuln.method} |")
                lines.append(f"| OWASP Category | {vuln.owasp_category} |")
                lines.append("")

                if vuln.payload:
                    lines.append("**Payload:**")
                    lines.append("```")
                    lines.append(vuln.payload)
                    lines.append("```")
                    lines.append("")

                if vuln.indicators:
                    lines.append("**Detection Indicators:**")
                    for indicator in vuln.indicators[:5]:
                        lines.append(f"- `{indicator[:100]}`")
                    lines.append("")

                if vuln.reasoning:
                    lines.append("**AI Reasoning:**")
                    for step in vuln.reasoning[:5]:
                        lines.append(f"- {step}")
                    lines.append("")

                lines.append("**Remediation:**")
                lines.append(f"> {vuln.get_remediation()}")
                lines.append("")
                lines.append("---")
                lines.append("")

        # Recommendations
        lines.append("## Recommendations")
        lines.append("")

        # Group by type
        by_type = result.get_vulnerabilities_by_type()
        if by_type:
            for vuln_type, vulns in by_type.items():
                if vulns:
                    lines.append(f"### {vuln_type.upper()}")
                    lines.append(f"- {vulns[0].get_remediation()}")
                    lines.append(f"- Affected parameters: {', '.join(set(v.parameter for v in vulns))}")
                    lines.append("")
        else:
            lines.append("No specific recommendations - no vulnerabilities found.")
            lines.append("")

        # Footer
        lines.append("---")
        lines.append("*Report generated by AI Security Agents Framework*")

        return "\n".join(lines)

    def _severity_emoji(self, severity: Severity) -> str:
        """Get emoji for severity level."""
        emojis = {
            Severity.CRITICAL: "🔴",
            Severity.HIGH: "🟠",
            Severity.MEDIUM: "🟡",
            Severity.LOW: "🟢",
            Severity.INFORMATIONAL: "🔵",
        }
        return emojis.get(severity, "⚪")

    def to_string(self, result: ScanResult) -> str:
        """Render scan result to Markdown string."""
        return self._render(result)
