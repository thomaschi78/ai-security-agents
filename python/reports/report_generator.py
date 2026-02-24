"""Multi-format report generator."""

from pathlib import Path
from typing import List, Optional
from datetime import datetime

from .json_writer import JSONWriter
from .html_writer import HTMLWriter
from .markdown_writer import MarkdownWriter
from .sqlite_writer import SQLiteWriter, query_database
from ..results import ScanResult


class ReportGenerator:
    """
    Generates security scan reports in multiple formats.

    Supported formats:
    - JSON: Machine-readable with full details
    - HTML: Interactive report with styling
    - Markdown: Human-readable documentation
    - SQLite: Queryable database
    """

    def __init__(
        self,
        output_dir: str = "./reports",
        template_dir: Optional[str] = None
    ):
        self.output_dir = Path(output_dir)
        self.template_dir = template_dir

        # Initialize writers
        self._json_writer = JSONWriter()
        self._html_writer = HTMLWriter(template_dir=template_dir) if template_dir else HTMLWriter()
        self._markdown_writer = MarkdownWriter()
        self._sqlite_writer = SQLiteWriter()

    def generate(
        self,
        result: ScanResult,
        formats: Optional[List[str]] = None,
        base_name: Optional[str] = None
    ) -> dict:
        """
        Generate reports in specified formats.

        Args:
            result: Scan result to report on
            formats: List of formats (json, html, markdown, sqlite)
            base_name: Base filename (default: scan ID)

        Returns:
            Dict mapping format to output path
        """
        if formats is None:
            formats = ["json", "html", "markdown", "sqlite"]

        base_name = base_name or f"report_{result.id[:8]}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}"

        self.output_dir.mkdir(parents=True, exist_ok=True)

        paths = {}

        for fmt in formats:
            fmt = fmt.lower()

            if fmt == "json":
                path = self.output_dir / f"{base_name}.json"
                paths["json"] = self._json_writer.write(result, str(path))

            elif fmt == "html":
                path = self.output_dir / f"{base_name}.html"
                paths["html"] = self._html_writer.write(result, str(path))

            elif fmt in ("markdown", "md"):
                path = self.output_dir / f"{base_name}.md"
                paths["markdown"] = self._markdown_writer.write(result, str(path))

            elif fmt in ("sqlite", "db"):
                path = self.output_dir / f"{base_name}.db"
                paths["sqlite"] = self._sqlite_writer.write(result, str(path))

        return paths

    def generate_json(self, result: ScanResult, output_path: Optional[str] = None) -> str:
        """Generate JSON report."""
        if output_path is None:
            output_path = str(self.output_dir / f"report_{result.id[:8]}.json")
        return self._json_writer.write(result, output_path)

    def generate_html(self, result: ScanResult, output_path: Optional[str] = None) -> str:
        """Generate HTML report."""
        if output_path is None:
            output_path = str(self.output_dir / f"report_{result.id[:8]}.html")
        return self._html_writer.write(result, output_path)

    def generate_markdown(self, result: ScanResult, output_path: Optional[str] = None) -> str:
        """Generate Markdown report."""
        if output_path is None:
            output_path = str(self.output_dir / f"report_{result.id[:8]}.md")
        return self._markdown_writer.write(result, output_path)

    def generate_sqlite(self, result: ScanResult, output_path: Optional[str] = None) -> str:
        """Generate SQLite database."""
        if output_path is None:
            output_path = str(self.output_dir / f"report_{result.id[:8]}.db")
        return self._sqlite_writer.write(result, output_path)

    def to_string(self, result: ScanResult, format: str = "json") -> str:
        """Convert result to string in specified format."""
        format = format.lower()

        if format == "json":
            return self._json_writer.to_string(result)
        elif format == "html":
            return self._html_writer.to_string(result)
        elif format in ("markdown", "md"):
            return self._markdown_writer.to_string(result)
        else:
            raise ValueError(f"Unsupported string format: {format}")
