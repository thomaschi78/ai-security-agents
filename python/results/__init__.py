"""Result models and aggregation."""

from .vulnerability import Vulnerability, Severity, Confidence, CWE_SEVERITY
from .finding import ScanTarget, ScanResult
from .result_aggregator import ResultAggregator

__all__ = [
    "Vulnerability",
    "Severity",
    "Confidence",
    "CWE_SEVERITY",
    "ScanTarget",
    "ScanResult",
    "ResultAggregator",
]
