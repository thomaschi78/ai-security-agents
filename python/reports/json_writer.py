"""JSON report writer."""

import json
from pathlib import Path
from typing import Any, Dict, Optional
from datetime import datetime

from ..results import ScanResult


class JSONWriter:
    """Writes scan results to JSON format."""

    def __init__(self, pretty_print: bool = True, include_evidence: bool = True):
        self.pretty_print = pretty_print
        self.include_evidence = include_evidence

    def write(self, result: ScanResult, output_path: str) -> str:
        """
        Write scan result to JSON file.

        Args:
            result: Scan result to write
            output_path: Output file path

        Returns:
            Path to written file
        """
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)

        data = self._format_result(result)

        with open(path, "w") as f:
            if self.pretty_print:
                json.dump(data, f, indent=2, default=str)
            else:
                json.dump(data, f, default=str)

        return str(path)

    def _format_result(self, result: ScanResult) -> Dict[str, Any]:
        """Format scan result for JSON output."""
        data = {
            "metadata": {
                "report_type": "security_scan",
                "generated_at": datetime.utcnow().isoformat(),
                "scan_id": result.id,
                "framework": "AI Security Agents",
                "version": "1.0.0",
            },
            "scan": {
                "target": result.target.to_dict() if result.target else None,
                "start_time": result.start_time.isoformat(),
                "end_time": result.end_time.isoformat() if result.end_time else None,
                "duration_seconds": result.duration_seconds,
                "status": "complete" if result.is_complete else "incomplete",
            },
            "summary": result.get_summary(),
            "vulnerabilities": [],
        }

        # Add vulnerabilities
        for vuln in result.vulnerabilities:
            vuln_data = vuln.to_dict()

            # Optionally exclude evidence for smaller reports
            if not self.include_evidence:
                vuln_data.pop("evidence", None)
                vuln_data.pop("response_snippet", None)

            data["vulnerabilities"].append(vuln_data)

        # Group by severity for quick reference
        data["by_severity"] = result.get_vulnerabilities_by_severity()
        data["by_type"] = result.get_vulnerabilities_by_type()

        return data

    def to_string(self, result: ScanResult) -> str:
        """Convert scan result to JSON string."""
        data = self._format_result(result)
        if self.pretty_print:
            return json.dumps(data, indent=2, default=str)
        return json.dumps(data, default=str)
