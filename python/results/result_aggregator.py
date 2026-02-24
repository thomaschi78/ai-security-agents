"""Result aggregation and deduplication."""

from typing import Any, Dict, List, Optional, Set
from datetime import datetime
import hashlib

from .vulnerability import Vulnerability, Severity, Confidence
from .finding import ScanResult, ScanTarget


class ResultAggregator:
    """
    Aggregates findings from multiple agents with deduplication.

    Features:
    - Deduplication based on URL + parameter + vulnerability type
    - Severity ranking
    - Chain tracking
    - Multi-scan aggregation
    """

    def __init__(self):
        self._findings: Dict[str, Vulnerability] = {}  # Keyed by dedup hash
        self._chains: Dict[str, List[str]] = {}  # Chain relationships
        self._scan_results: List[ScanResult] = []
        self._seen_hashes: Set[str] = set()

    def add_finding(self, finding: Vulnerability) -> bool:
        """
        Add a finding with deduplication.

        Args:
            finding: Vulnerability to add

        Returns:
            True if finding was added (not duplicate)
        """
        dedup_hash = self._compute_hash(finding)

        if dedup_hash in self._seen_hashes:
            # Update existing if higher confidence
            existing = self._findings.get(dedup_hash)
            if existing and finding.confidence_score > existing.confidence_score:
                self._findings[dedup_hash] = finding
                return False
            return False

        self._seen_hashes.add(dedup_hash)
        self._findings[dedup_hash] = finding

        # Track chains
        if finding.chained_from:
            self._chains.setdefault(finding.chained_from, []).append(finding.id)

        return True

    def add_findings(self, findings: List[Vulnerability]) -> int:
        """Add multiple findings, returning count of new findings."""
        return sum(1 for f in findings if self.add_finding(f))

    def _compute_hash(self, finding: Vulnerability) -> str:
        """Compute deduplication hash for a finding."""
        key = f"{finding.url}|{finding.parameter}|{finding.vulnerability_type}|{finding.method}"
        return hashlib.sha256(key.encode()).hexdigest()[:16]

    def get_all_findings(self) -> List[Vulnerability]:
        """Get all unique findings."""
        return list(self._findings.values())

    def get_findings_by_severity(self, severity: Severity) -> List[Vulnerability]:
        """Get findings filtered by severity."""
        return [f for f in self._findings.values() if f.severity == severity]

    def get_findings_by_type(self, vuln_type: str) -> List[Vulnerability]:
        """Get findings filtered by vulnerability type."""
        return [f for f in self._findings.values() if f.vulnerability_type == vuln_type]

    def get_findings_by_url(self, url: str) -> List[Vulnerability]:
        """Get findings for a specific URL."""
        return [f for f in self._findings.values() if f.url == url]

    def get_chained_findings(self, parent_id: str) -> List[Vulnerability]:
        """Get findings that were chained from a parent finding."""
        chained_ids = self._chains.get(parent_id, [])
        return [f for f in self._findings.values() if f.id in chained_ids]

    def get_ranked_findings(self) -> List[Vulnerability]:
        """Get findings sorted by severity and confidence."""
        severity_order = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
            Severity.INFORMATIONAL: 4,
        }

        return sorted(
            self._findings.values(),
            key=lambda f: (severity_order.get(f.severity, 5), -f.confidence_score)
        )

    def get_summary(self) -> Dict[str, Any]:
        """Get aggregation summary."""
        findings = self.get_all_findings()

        by_severity = {}
        by_type = {}

        for f in findings:
            by_severity[f.severity.value] = by_severity.get(f.severity.value, 0) + 1
            by_type[f.vulnerability_type] = by_type.get(f.vulnerability_type, 0) + 1

        return {
            "total_findings": len(findings),
            "unique_urls": len(set(f.url for f in findings)),
            "by_severity": by_severity,
            "by_type": by_type,
            "chains": len(self._chains),
            "duplicates_filtered": len(self._seen_hashes) - len(self._findings),
        }

    def create_scan_result(
        self,
        target: Optional[ScanTarget] = None,
        agents_used: Optional[List[str]] = None,
        payloads_tested: int = 0,
        metadata: Optional[Dict[str, Any]] = None
    ) -> ScanResult:
        """Create a ScanResult from aggregated findings."""
        result = ScanResult(
            target=target,
            vulnerabilities=self.get_all_findings(),
            agents_used=agents_used or [],
            payloads_tested=payloads_tested,
            metadata=metadata or {},
        )
        result.complete()
        self._scan_results.append(result)
        return result

    def merge_results(self, other: "ResultAggregator") -> int:
        """Merge findings from another aggregator."""
        return self.add_findings(other.get_all_findings())

    def clear(self) -> None:
        """Clear all aggregated findings."""
        self._findings.clear()
        self._chains.clear()
        self._seen_hashes.clear()

    def export_findings(self) -> List[Dict[str, Any]]:
        """Export all findings as dictionaries."""
        return [f.to_dict() for f in self.get_ranked_findings()]
