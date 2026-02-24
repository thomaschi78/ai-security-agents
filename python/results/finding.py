"""Finding data model for scan results."""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional
import uuid

from .vulnerability import Vulnerability, Severity


@dataclass
class ScanTarget:
    """Represents a scan target."""
    url: str
    parameters: List[Dict[str, str]] = field(default_factory=list)
    method: str = "GET"
    headers: Dict[str, str] = field(default_factory=dict)
    cookies: Dict[str, str] = field(default_factory=dict)
    body: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "parameters": self.parameters,
            "method": self.method,
            "headers": self.headers,
            "cookies": self.cookies,
            "body": self.body,
        }


@dataclass
class ScanResult:
    """Results from a complete scan."""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    target: Optional[ScanTarget] = None
    start_time: datetime = field(default_factory=datetime.utcnow)
    end_time: Optional[datetime] = None
    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    agents_used: List[str] = field(default_factory=list)
    payloads_tested: int = 0
    errors: List[Dict[str, Any]] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def add_vulnerability(self, vuln: Vulnerability) -> None:
        """Add a vulnerability to results."""
        self.vulnerabilities.append(vuln)

    def complete(self) -> None:
        """Mark scan as complete."""
        self.end_time = datetime.utcnow()

    @property
    def duration_seconds(self) -> float:
        """Get scan duration in seconds."""
        if not self.end_time:
            return (datetime.utcnow() - self.start_time).total_seconds()
        return (self.end_time - self.start_time).total_seconds()

    @property
    def is_complete(self) -> bool:
        """Check if scan is complete."""
        return self.end_time is not None

    @property
    def vulnerability_count(self) -> int:
        """Get total vulnerability count."""
        return len(self.vulnerabilities)

    @property
    def critical_count(self) -> int:
        """Get critical vulnerability count."""
        return len([v for v in self.vulnerabilities if v.severity == Severity.CRITICAL])

    @property
    def high_count(self) -> int:
        """Get high severity vulnerability count."""
        return len([v for v in self.vulnerabilities if v.severity == Severity.HIGH])

    @property
    def medium_count(self) -> int:
        """Get medium severity vulnerability count."""
        return len([v for v in self.vulnerabilities if v.severity == Severity.MEDIUM])

    @property
    def low_count(self) -> int:
        """Get low severity vulnerability count."""
        return len([v for v in self.vulnerabilities if v.severity == Severity.LOW])

    def get_vulnerabilities_by_type(self) -> Dict[str, List[Vulnerability]]:
        """Group vulnerabilities by type."""
        by_type: Dict[str, List[Vulnerability]] = {}
        for vuln in self.vulnerabilities:
            by_type.setdefault(vuln.vulnerability_type, []).append(vuln)
        return by_type

    def get_vulnerabilities_by_severity(self) -> Dict[str, List[Vulnerability]]:
        """Group vulnerabilities by severity."""
        by_severity: Dict[str, List[Vulnerability]] = {}
        for vuln in self.vulnerabilities:
            by_severity.setdefault(vuln.severity.value, []).append(vuln)
        return by_severity

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "target": self.target.to_dict() if self.target else None,
            "start_time": self.start_time.isoformat(),
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "duration_seconds": self.duration_seconds,
            "is_complete": self.is_complete,
            "vulnerabilities": [v.to_dict() for v in self.vulnerabilities],
            "vulnerability_count": self.vulnerability_count,
            "severity_summary": {
                "critical": self.critical_count,
                "high": self.high_count,
                "medium": self.medium_count,
                "low": self.low_count,
            },
            "agents_used": self.agents_used,
            "payloads_tested": self.payloads_tested,
            "errors": self.errors,
            "metadata": self.metadata,
        }

    def get_summary(self) -> Dict[str, Any]:
        """Get scan summary."""
        return {
            "target_url": self.target.url if self.target else "N/A",
            "duration": f"{self.duration_seconds:.2f}s",
            "status": "Complete" if self.is_complete else "In Progress",
            "total_findings": self.vulnerability_count,
            "critical": self.critical_count,
            "high": self.high_count,
            "medium": self.medium_count,
            "low": self.low_count,
            "payloads_tested": self.payloads_tested,
            "agents_used": len(self.agents_used),
            "errors": len(self.errors),
        }
