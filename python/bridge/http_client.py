"""Async HTTP client for sending payloads."""

import asyncio
import time
from typing import Any, Dict, List, Optional
from urllib.parse import urlencode, urlparse, parse_qs, urlunparse
import logging

try:
    import aiohttp
    AIOHTTP_AVAILABLE = True
except ImportError:
    AIOHTTP_AVAILABLE = False

logger = logging.getLogger(__name__)


class HTTPClient:
    """
    Async HTTP client for security testing.

    Features:
    - Async request handling
    - Response timing
    - Header/cookie management
    - Request logging
    """

    def __init__(
        self,
        timeout: float = 30.0,
        follow_redirects: bool = False,
        max_retries: int = 2,
        user_agent: str = "AI-Security-Agent/1.0",
        verify_ssl: bool = False
    ):
        if not AIOHTTP_AVAILABLE:
            raise ImportError("aiohttp package required. Run: pip install aiohttp")

        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self.follow_redirects = follow_redirects
        self.max_retries = max_retries
        self.user_agent = user_agent
        self.verify_ssl = verify_ssl

        self._session: Optional[aiohttp.ClientSession] = None
        self._request_count = 0

    async def __aenter__(self):
        await self.start()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()

    async def start(self) -> None:
        """Start the HTTP session."""
        if self._session is None:
            connector = aiohttp.TCPConnector(ssl=self.verify_ssl)
            self._session = aiohttp.ClientSession(
                timeout=self.timeout,
                connector=connector,
                headers={"User-Agent": self.user_agent}
            )

    async def close(self) -> None:
        """Close the HTTP session."""
        if self._session:
            await self._session.close()
            self._session = None

    async def send_request(
        self,
        url: str,
        method: str = "GET",
        parameter: str = "",
        payload: str = "",
        headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None,
        body: Optional[str] = None,
        inject_in: str = "query"  # query, body, header, cookie
    ) -> Dict[str, Any]:
        """
        Send HTTP request with payload injection.

        Args:
            url: Target URL
            method: HTTP method
            parameter: Parameter to inject into
            payload: Payload to inject
            headers: Additional headers
            cookies: Cookies to send
            body: Request body (for POST)
            inject_in: Where to inject payload

        Returns:
            Response data dictionary
        """
        if self._session is None:
            await self.start()

        start_time = time.time()

        try:
            # Prepare request with payload injection
            prepared_url, prepared_headers, prepared_body = self._prepare_request(
                url, method, parameter, payload, headers, body, inject_in
            )

            # Build request kwargs
            kwargs = {
                "headers": prepared_headers or {},
                "allow_redirects": self.follow_redirects,
            }

            if cookies:
                kwargs["cookies"] = cookies

            if method.upper() in ("POST", "PUT", "PATCH") and prepared_body:
                kwargs["data"] = prepared_body

            # Send request
            async with self._session.request(method, prepared_url, **kwargs) as response:
                body_text = await response.text()
                elapsed = (time.time() - start_time) * 1000

                self._request_count += 1

                return {
                    "status_code": response.status,
                    "headers": dict(response.headers),
                    "body": body_text,
                    "content_type": response.content_type or "",
                    "time_ms": elapsed,
                    "url": str(response.url),
                }

        except asyncio.TimeoutError:
            return {
                "status_code": 0,
                "headers": {},
                "body": "",
                "content_type": "",
                "time_ms": (time.time() - start_time) * 1000,
                "error": "Timeout",
            }

        except Exception as e:
            logger.error(f"Request failed: {e}")
            return {
                "status_code": 0,
                "headers": {},
                "body": "",
                "content_type": "",
                "time_ms": (time.time() - start_time) * 1000,
                "error": str(e),
            }

    def _prepare_request(
        self,
        url: str,
        method: str,
        parameter: str,
        payload: str,
        headers: Optional[Dict[str, str]],
        body: Optional[str],
        inject_in: str
    ) -> tuple:
        """Prepare request with payload injection."""
        prepared_url = url
        prepared_headers = headers.copy() if headers else {}
        prepared_body = body

        if inject_in == "query":
            # Inject into URL query parameter
            parsed = urlparse(url)
            params = parse_qs(parsed.query, keep_blank_values=True)

            if parameter:
                params[parameter] = [payload]
            else:
                # Append payload to first parameter
                if params:
                    first_key = list(params.keys())[0]
                    params[first_key] = [params[first_key][0] + payload if params[first_key] else payload]

            new_query = urlencode(params, doseq=True)
            prepared_url = urlunparse(parsed._replace(query=new_query))

        elif inject_in == "body":
            # Inject into request body
            if body and parameter:
                # Try to find and replace parameter value
                if f"{parameter}=" in body:
                    # URL-encoded body
                    params = parse_qs(body, keep_blank_values=True)
                    params[parameter] = [payload]
                    prepared_body = urlencode(params, doseq=True)
                else:
                    # Just append
                    prepared_body = body + payload
            else:
                prepared_body = payload

        elif inject_in == "header":
            # Inject into header
            if parameter:
                prepared_headers[parameter] = payload

        elif inject_in == "cookie":
            # Inject into cookie (via Cookie header)
            cookie_header = prepared_headers.get("Cookie", "")
            if parameter:
                if cookie_header:
                    prepared_headers["Cookie"] = f"{cookie_header}; {parameter}={payload}"
                else:
                    prepared_headers["Cookie"] = f"{parameter}={payload}"

        return prepared_url, prepared_headers, prepared_body

    def get_stats(self) -> Dict[str, Any]:
        """Get client statistics."""
        return {
            "requests_sent": self._request_count,
            "session_active": self._session is not None,
        }


class MockHTTPClient:
    """Mock HTTP client for testing without network."""

    def __init__(self):
        self._responses: Dict[str, Dict[str, Any]] = {}
        self._default_response = {
            "status_code": 200,
            "headers": {"Content-Type": "text/html"},
            "body": "<html><body>Test response</body></html>",
            "content_type": "text/html",
            "time_ms": 50.0,
        }

    async def send_request(self, **kwargs) -> Dict[str, Any]:
        """Return mock response."""
        url = kwargs.get("url", "")
        payload = kwargs.get("payload", "")

        # Check for registered responses
        if url in self._responses:
            return self._responses[url]

        # Simple vulnerability simulation
        response = self._default_response.copy()

        # Simulate SQL error
        if "'" in payload and ("OR" in payload.upper() or "UNION" in payload.upper()):
            response["body"] = "Error: You have an error in your SQL syntax"

        # Simulate XSS reflection
        if "<script>" in payload.lower():
            response["body"] = f"<html><body>Search: {payload}</body></html>"

        return response

    def add_response(self, url: str, response: Dict[str, Any]) -> None:
        """Add a mock response for a URL."""
        self._responses[url] = response

    async def start(self) -> None:
        pass

    async def close(self) -> None:
        pass
