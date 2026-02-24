"""Payload loading from files and ZAP fuzzdb."""

from pathlib import Path
from typing import Dict, List, Optional
import json
import logging

logger = logging.getLogger(__name__)


class PayloadLoader:
    """
    Loads payloads from various sources.

    Sources:
    - Local payload files
    - ZAP fuzzdb directory
    - Built-in payloads
    """

    def __init__(
        self,
        payload_dir: Optional[str] = None,
        zap_fuzzers_path: Optional[str] = None
    ):
        self.payload_dir = Path(payload_dir) if payload_dir else None
        self.zap_fuzzers_path = Path(zap_fuzzers_path) if zap_fuzzers_path else None

        self._cache: Dict[str, List[str]] = {}

    def load_from_file(self, filepath: str, encoding: str = "utf-8") -> List[str]:
        """
        Load payloads from a text file (one per line).

        Args:
            filepath: Path to payload file
            encoding: File encoding

        Returns:
            List of payloads
        """
        cache_key = f"file:{filepath}"
        if cache_key in self._cache:
            return self._cache[cache_key]

        payloads = []
        path = Path(filepath)

        if not path.exists():
            logger.warning(f"Payload file not found: {filepath}")
            return payloads

        try:
            with open(path, "r", encoding=encoding, errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        payloads.append(line)

            self._cache[cache_key] = payloads
            logger.info(f"Loaded {len(payloads)} payloads from {filepath}")

        except Exception as e:
            logger.error(f"Error loading payloads from {filepath}: {e}")

        return payloads

    def load_from_json(self, filepath: str) -> Dict[str, List[str]]:
        """
        Load categorized payloads from JSON file.

        Args:
            filepath: Path to JSON payload file

        Returns:
            Dict mapping category to payload list
        """
        path = Path(filepath)

        if not path.exists():
            logger.warning(f"Payload JSON not found: {filepath}")
            return {}

        try:
            with open(path, "r") as f:
                data = json.load(f)
            return data

        except Exception as e:
            logger.error(f"Error loading JSON payloads from {filepath}: {e}")
            return {}

    def load_zap_fuzzdb(
        self,
        category: str,
        subcategory: Optional[str] = None
    ) -> List[str]:
        """
        Load payloads from ZAP fuzzdb.

        Args:
            category: Main category (e.g., "attack", "discovery")
            subcategory: Subcategory (e.g., "sql-injection")

        Returns:
            List of payloads
        """
        if not self.zap_fuzzers_path:
            logger.warning("ZAP fuzzers path not configured")
            return []

        # Build path
        fuzzer_path = self.zap_fuzzers_path / category
        if subcategory:
            fuzzer_path = fuzzer_path / subcategory

        payloads = []

        if fuzzer_path.is_file():
            return self.load_from_file(str(fuzzer_path))

        if fuzzer_path.is_dir():
            # Load all files in directory
            for file_path in fuzzer_path.glob("**/*.txt"):
                payloads.extend(self.load_from_file(str(file_path)))

        return payloads

    def load_by_vulnerability_type(self, vuln_type: str) -> List[str]:
        """
        Load payloads for a specific vulnerability type.

        Args:
            vuln_type: Vulnerability type (sqli, xss, cmdi, etc.)

        Returns:
            List of payloads
        """
        # Map vulnerability types to fuzzdb paths
        fuzzdb_mapping = {
            "sqli": ("attack", "sql-injection"),
            "xss": ("attack", "xss"),
            "cmdi": ("attack", "os-cmd-execution"),
            "lfi": ("attack", "lfi"),
            "path_traversal": ("attack", "path-traversal"),
            "xxe": ("attack", "xxe"),
            "ssti": ("attack", "template-injection"),
        }

        if vuln_type in fuzzdb_mapping:
            category, subcategory = fuzzdb_mapping[vuln_type]
            return self.load_zap_fuzzdb(category, subcategory)

        # Try loading from local payload directory
        if self.payload_dir:
            payload_file = self.payload_dir / f"{vuln_type}.txt"
            if payload_file.exists():
                return self.load_from_file(str(payload_file))

        return []

    def get_available_categories(self) -> List[str]:
        """Get list of available payload categories."""
        categories = []

        if self.zap_fuzzers_path and self.zap_fuzzers_path.exists():
            for path in self.zap_fuzzers_path.iterdir():
                if path.is_dir():
                    categories.append(path.name)

        if self.payload_dir and self.payload_dir.exists():
            for path in self.payload_dir.glob("*.txt"):
                categories.append(path.stem)

        return sorted(set(categories))

    def clear_cache(self) -> None:
        """Clear the payload cache."""
        self._cache.clear()


# Default payload sets for common vulnerabilities
DEFAULT_SQLI_PAYLOADS = [
    "'",
    "\"",
    "' OR '1'='1",
    "\" OR \"1\"=\"1",
    "1' OR '1'='1' --",
    "' UNION SELECT NULL--",
    "'; DROP TABLE test--",
]

DEFAULT_XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "javascript:alert(1)",
    "'\"><script>alert(1)</script>",
]

DEFAULT_CMDI_PAYLOADS = [
    ";id",
    "|id",
    "$(id)",
    "`id`",
    ";cat /etc/passwd",
]


def get_default_payloads(vuln_type: str) -> List[str]:
    """Get default payloads for a vulnerability type."""
    defaults = {
        "sqli": DEFAULT_SQLI_PAYLOADS,
        "xss": DEFAULT_XSS_PAYLOADS,
        "cmdi": DEFAULT_CMDI_PAYLOADS,
    }
    return defaults.get(vuln_type, [])
