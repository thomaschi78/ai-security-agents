"""Claude API client for vulnerability reasoning."""

import asyncio
import logging
from typing import Any, Dict, List, Optional
from datetime import datetime
import json

try:
    import anthropic
    ANTHROPIC_AVAILABLE = True
except ImportError:
    ANTHROPIC_AVAILABLE = False

from .prompt_templates import build_analysis_prompt, build_chaining_prompt
from .response_parser import parse_analysis_response, parse_chaining_response

logger = logging.getLogger(__name__)


class ClaudeClientError(Exception):
    """Error communicating with Claude API."""
    pass


class ClaudeClient:
    """
    Async Claude API client for security analysis.

    Provides methods for vulnerability analysis and chaining recommendations.
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        model: str = "claude-sonnet-4-20250514",
        max_tokens: int = 2048,
        temperature: float = 0.3,
        timeout: float = 60.0,
        max_retries: int = 3
    ):
        """
        Initialize Claude client.

        Args:
            api_key: Anthropic API key (or set ANTHROPIC_API_KEY env var)
            model: Model to use for analysis
            max_tokens: Maximum tokens in response
            temperature: Sampling temperature (lower = more focused)
            timeout: Request timeout in seconds
            max_retries: Number of retries on failure
        """
        if not ANTHROPIC_AVAILABLE:
            raise ImportError("anthropic package not installed. Run: pip install anthropic")

        self.model = model
        self.max_tokens = max_tokens
        self.temperature = temperature
        self.timeout = timeout
        self.max_retries = max_retries

        self._client = anthropic.AsyncAnthropic(api_key=api_key)

        # Stats tracking
        self._stats = {
            "requests": 0,
            "tokens_input": 0,
            "tokens_output": 0,
            "errors": 0,
            "cache_hits": 0,
        }

        # Simple response cache
        self._cache: Dict[str, Dict[str, Any]] = {}
        self._cache_ttl = 300  # 5 minutes

    async def analyze_response(
        self,
        vulnerability_type: str,
        payload: str,
        response_body: str,
        status_code: int,
        error_indicators: List[str],
        pattern_matches: List[Dict[str, Any]],
        current_stage: str,
        context: Dict[str, Any],
        cweid: int = 0
    ) -> Dict[str, Any]:
        """
        Analyze HTTP response for vulnerability indicators.

        Args:
            vulnerability_type: Type of vulnerability being tested
            payload: Payload that was sent
            response_body: HTTP response body
            status_code: HTTP status code
            error_indicators: Pre-detected error indicators
            pattern_matches: Pre-detected pattern matches
            current_stage: Current testing stage
            context: Additional context
            cweid: CWE ID for the vulnerability

        Returns:
            Analysis result with decision, confidence, reasoning
        """
        # Build prompt
        prompt = build_analysis_prompt(
            vulnerability_type=vulnerability_type,
            cweid=cweid,
            payload=payload,
            response_body=response_body,
            status_code=status_code,
            error_indicators=error_indicators,
            pattern_matches=pattern_matches,
            current_stage=current_stage,
            context=context
        )

        # Check cache
        cache_key = self._make_cache_key(prompt)
        cached = self._get_cached(cache_key)
        if cached:
            self._stats["cache_hits"] += 1
            return cached

        # Make API request
        response = await self._make_request(prompt)

        # Parse response
        result = parse_analysis_response(response)

        # Cache result
        self._cache_result(cache_key, result)

        return result

    async def analyze_chaining(
        self,
        source_vuln: str,
        source_cweid: int,
        url: str,
        parameter: str,
        confidence: float,
        evidence: str
    ) -> List[Dict[str, Any]]:
        """
        Analyze potential vulnerability chaining opportunities.

        Args:
            source_vuln: Confirmed vulnerability type
            source_cweid: CWE ID of source vulnerability
            url: Target URL
            parameter: Vulnerable parameter
            confidence: Confidence in source vulnerability
            evidence: Evidence of the vulnerability

        Returns:
            List of chain recommendations
        """
        prompt = build_chaining_prompt(
            source_vuln=source_vuln,
            source_cweid=source_cweid,
            url=url,
            parameter=parameter,
            confidence=confidence,
            evidence=evidence
        )

        response = await self._make_request(prompt)
        return parse_chaining_response(response)

    async def _make_request(self, prompt: str) -> str:
        """
        Make API request with retries.

        Args:
            prompt: Prompt to send

        Returns:
            Response text
        """
        last_error = None

        for attempt in range(self.max_retries):
            try:
                self._stats["requests"] += 1

                response = await asyncio.wait_for(
                    self._client.messages.create(
                        model=self.model,
                        max_tokens=self.max_tokens,
                        temperature=self.temperature,
                        messages=[
                            {"role": "user", "content": prompt}
                        ]
                    ),
                    timeout=self.timeout
                )

                # Track token usage
                if hasattr(response, "usage"):
                    self._stats["tokens_input"] += response.usage.input_tokens
                    self._stats["tokens_output"] += response.usage.output_tokens

                # Extract text from response
                if response.content and len(response.content) > 0:
                    return response.content[0].text

                raise ClaudeClientError("Empty response from Claude")

            except asyncio.TimeoutError:
                last_error = "Request timeout"
                logger.warning(f"Claude request timeout (attempt {attempt + 1})")
            except anthropic.RateLimitError as e:
                last_error = str(e)
                wait_time = 2 ** attempt
                logger.warning(f"Rate limited, waiting {wait_time}s")
                await asyncio.sleep(wait_time)
            except anthropic.APIError as e:
                last_error = str(e)
                logger.error(f"Claude API error: {e}")
                self._stats["errors"] += 1

        raise ClaudeClientError(f"Failed after {self.max_retries} attempts: {last_error}")

    def _make_cache_key(self, prompt: str) -> str:
        """Create cache key from prompt."""
        import hashlib
        return hashlib.sha256(prompt.encode()).hexdigest()[:32]

    def _get_cached(self, key: str) -> Optional[Dict[str, Any]]:
        """Get cached result if still valid."""
        if key not in self._cache:
            return None

        cached = self._cache[key]
        if datetime.utcnow().timestamp() - cached["timestamp"] > self._cache_ttl:
            del self._cache[key]
            return None

        return cached["result"]

    def _cache_result(self, key: str, result: Dict[str, Any]) -> None:
        """Cache a result."""
        self._cache[key] = {
            "result": result,
            "timestamp": datetime.utcnow().timestamp()
        }

        # Limit cache size
        if len(self._cache) > 1000:
            oldest_key = min(self._cache.keys(), key=lambda k: self._cache[k]["timestamp"])
            del self._cache[oldest_key]

    def get_stats(self) -> Dict[str, Any]:
        """Get client statistics."""
        return {
            **self._stats,
            "cache_size": len(self._cache),
            "model": self.model,
        }

    def clear_cache(self) -> None:
        """Clear response cache."""
        self._cache.clear()


class MockClaudeClient:
    """Mock Claude client for testing without API calls."""

    def __init__(self):
        self._stats = {"requests": 0}

    async def analyze_response(self, **kwargs) -> Dict[str, Any]:
        """Return mock analysis response."""
        self._stats["requests"] += 1

        # Simple heuristic-based mock response
        pattern_matches = kwargs.get("pattern_matches", [])
        error_indicators = kwargs.get("error_indicators", [])

        confidence = 0.1
        if pattern_matches:
            confidence += 0.3 * len(pattern_matches)
        if error_indicators:
            confidence += 0.1 * len(error_indicators)

        confidence = min(confidence, 1.0)

        if confidence >= 0.7:
            decision = "REPORT"
        elif confidence >= 0.4:
            decision = "ESCALATE"
        else:
            decision = "CONTINUE"

        return {
            "decision": decision,
            "confidence": confidence,
            "reasoning": ["Mock analysis based on pattern matches"],
            "indicators": [m.get("match", "") for m in pattern_matches],
            "suggested_payloads": [],
            "chain_opportunities": [],
        }

    async def analyze_chaining(self, **kwargs) -> List[Dict[str, Any]]:
        """Return mock chaining response."""
        return []

    def get_stats(self) -> Dict[str, Any]:
        return self._stats
