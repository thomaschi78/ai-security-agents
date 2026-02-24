"""ZAP REST API client for integration with OWASP ZAP."""

import asyncio
from typing import Any, Dict, List, Optional
import logging

try:
    import aiohttp
    AIOHTTP_AVAILABLE = True
except ImportError:
    AIOHTTP_AVAILABLE = False

logger = logging.getLogger(__name__)


class ZAPClient:
    """
    Client for OWASP ZAP REST API.

    Provides integration with ZAP for:
    - Payload retrieval
    - Alert creation
    - Scan coordination
    - Session management
    """

    def __init__(
        self,
        zap_url: str = "http://localhost:8080",
        api_key: Optional[str] = None,
        timeout: float = 30.0
    ):
        if not AIOHTTP_AVAILABLE:
            raise ImportError("aiohttp package required")

        self.zap_url = zap_url.rstrip("/")
        self.api_key = api_key
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self._session: Optional[aiohttp.ClientSession] = None

    async def __aenter__(self):
        await self.start()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()

    async def start(self) -> None:
        """Start the client session."""
        if self._session is None:
            self._session = aiohttp.ClientSession(timeout=self.timeout)

    async def close(self) -> None:
        """Close the client session."""
        if self._session:
            await self._session.close()
            self._session = None

    async def _request(
        self,
        endpoint: str,
        method: str = "GET",
        params: Optional[Dict] = None,
        data: Optional[Dict] = None
    ) -> Dict[str, Any]:
        """Make API request to ZAP."""
        if self._session is None:
            await self.start()

        url = f"{self.zap_url}{endpoint}"

        # Add API key if configured
        if params is None:
            params = {}
        if self.api_key:
            params["apikey"] = self.api_key

        try:
            if method == "GET":
                async with self._session.get(url, params=params) as resp:
                    return await resp.json()
            else:
                async with self._session.post(url, params=params, data=data) as resp:
                    return await resp.json()

        except Exception as e:
            logger.error(f"ZAP API error: {e}")
            return {"error": str(e)}

    # Core API

    async def get_version(self) -> str:
        """Get ZAP version."""
        result = await self._request("/JSON/core/view/version/")
        return result.get("version", "unknown")

    async def get_alerts(
        self,
        base_url: Optional[str] = None,
        start: int = 0,
        count: int = 100
    ) -> List[Dict]:
        """Get alerts from ZAP."""
        params = {"start": start, "count": count}
        if base_url:
            params["baseurl"] = base_url

        result = await self._request("/JSON/core/view/alerts/", params=params)
        return result.get("alerts", [])

    async def add_alert(
        self,
        url: str,
        name: str,
        risk: int,  # 0=Info, 1=Low, 2=Medium, 3=High
        confidence: int,  # 0=FP, 1=Low, 2=Medium, 3=High, 4=Confirmed
        description: str,
        solution: str = "",
        reference: str = "",
        param: str = "",
        attack: str = "",
        evidence: str = "",
        cweid: int = 0,
        wascid: int = 0
    ) -> Dict:
        """Add an alert to ZAP."""
        params = {
            "url": url,
            "name": name,
            "risk": risk,
            "confidence": confidence,
            "description": description,
            "solution": solution,
            "reference": reference,
            "param": param,
            "attack": attack,
            "evidence": evidence[:500] if evidence else "",
            "cweid": cweid,
            "wascid": wascid,
        }

        return await self._request("/JSON/core/action/addAlert/", params=params)

    # Spider API

    async def spider_scan(
        self,
        url: str,
        max_children: int = 0,
        recurse: bool = True,
        subtree_only: bool = False
    ) -> str:
        """Start spider scan, returns scan ID."""
        params = {
            "url": url,
            "maxChildren": max_children,
            "recurse": recurse,
            "subtreeOnly": subtree_only,
        }
        result = await self._request("/JSON/spider/action/scan/", params=params)
        return result.get("scan", "")

    async def spider_status(self, scan_id: str) -> int:
        """Get spider scan progress (0-100)."""
        result = await self._request(
            "/JSON/spider/view/status/",
            params={"scanId": scan_id}
        )
        return int(result.get("status", 0))

    async def spider_results(self, scan_id: str) -> List[str]:
        """Get URLs found by spider."""
        result = await self._request(
            "/JSON/spider/view/results/",
            params={"scanId": scan_id}
        )
        return result.get("results", [])

    # Active Scan API

    async def active_scan(
        self,
        url: str,
        recurse: bool = True,
        in_scope_only: bool = False,
        scan_policy: str = ""
    ) -> str:
        """Start active scan, returns scan ID."""
        params = {
            "url": url,
            "recurse": recurse,
            "inScopeOnly": in_scope_only,
        }
        if scan_policy:
            params["scanPolicyName"] = scan_policy

        result = await self._request("/JSON/ascan/action/scan/", params=params)
        return result.get("scan", "")

    async def active_scan_status(self, scan_id: str) -> int:
        """Get active scan progress (0-100)."""
        result = await self._request(
            "/JSON/ascan/view/status/",
            params={"scanId": scan_id}
        )
        return int(result.get("status", 0))

    async def stop_scan(self, scan_id: str) -> Dict:
        """Stop an active scan."""
        return await self._request(
            "/JSON/ascan/action/stop/",
            params={"scanId": scan_id}
        )

    # Session API

    async def new_session(self, name: str = "", overwrite: bool = True) -> Dict:
        """Create new ZAP session."""
        return await self._request(
            "/JSON/core/action/newSession/",
            params={"name": name, "overwrite": overwrite}
        )

    async def save_session(self, name: str, overwrite: bool = True) -> Dict:
        """Save current ZAP session."""
        return await self._request(
            "/JSON/core/action/saveSession/",
            params={"name": name, "overwrite": overwrite}
        )

    # Payload Provider (requires AI Bridge extension)

    async def get_payloads(
        self,
        category: str,
        limit: int = 100
    ) -> List[str]:
        """
        Get payloads from ZAP's payload provider.

        Requires the AI Bridge extension to be installed.
        """
        result = await self._request(
            "/JSON/aibridge/view/payloads/",
            params={"category": category, "limit": limit}
        )
        return result.get("payloads", [])

    async def get_fuzzer_files(self) -> List[str]:
        """Get list of available fuzzer files."""
        result = await self._request("/JSON/aibridge/view/fuzzerFiles/")
        return result.get("files", [])


class ZAPAlertBridge:
    """Bridge to convert AI findings to ZAP alerts."""

    SEVERITY_MAP = {
        "critical": 3,
        "high": 3,
        "medium": 2,
        "low": 1,
        "informational": 0,
    }

    CONFIDENCE_MAP = {
        "confirmed": 4,
        "high": 3,
        "medium": 2,
        "low": 1,
        "false_positive": 0,
    }

    def __init__(self, zap_client: ZAPClient):
        self.zap_client = zap_client

    async def report_finding(self, vulnerability: Dict) -> Dict:
        """Report a finding to ZAP as an alert."""
        return await self.zap_client.add_alert(
            url=vulnerability.get("url", ""),
            name=f"AI-{vulnerability.get('vulnerability_type', 'Unknown').upper()}",
            risk=self.SEVERITY_MAP.get(vulnerability.get("severity", "medium"), 2),
            confidence=self.CONFIDENCE_MAP.get(
                vulnerability.get("confidence_level", "medium"), 2
            ),
            description=f"AI-detected {vulnerability.get('vulnerability_type')} vulnerability",
            solution=vulnerability.get("remediation", ""),
            param=vulnerability.get("parameter", ""),
            attack=vulnerability.get("payload", ""),
            evidence=vulnerability.get("evidence", ""),
            cweid=vulnerability.get("cweid", 0),
        )
