"""Bridge components for external integrations."""

from .http_client import HTTPClient, MockHTTPClient
from .zap_client import ZAPClient, ZAPAlertBridge

__all__ = [
    "HTTPClient",
    "MockHTTPClient",
    "ZAPClient",
    "ZAPAlertBridge",
]
