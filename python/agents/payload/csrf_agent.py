"""Cross-Site Request Forgery (CSRF) Agent - CWE-352."""

import re
from typing import Dict, List, Pattern

from ..base import BaseAgent, PayloadStage


class CSRFAgent(BaseAgent):
    """
    Cross-Site Request Forgery (CSRF) testing agent.

    Tests for CSRF vulnerabilities including:
    - Missing CSRF tokens
    - Predictable tokens
    - Token validation bypass
    - Same-site cookie issues

    Payloads derived from ZAP's CsrfTokenScanRule.java
    """

    @property
    def vulnerability_type(self) -> str:
        return "csrf"

    @property
    def cweid(self) -> int:
        return 352

    @property
    def priority(self) -> int:
        return 5  # Medium priority

    @property
    def staged_payloads(self) -> Dict[PayloadStage, List[str]]:
        # CSRF testing is more about removing/modifying tokens
        # rather than injecting payloads
        return {
            PayloadStage.PROBE: [
                # Empty token tests
                "",
                "null",
                "undefined",
                # Placeholder for actual token manipulation
                "__REMOVE_TOKEN__",  # Signal to remove CSRF token
                "__EMPTY_TOKEN__",   # Signal to set empty token
            ],
            PayloadStage.CONFIRM: [
                # Modified tokens
                "__INVALID_TOKEN__",
                "__RANDOM_TOKEN__",
                "__TRUNCATED_TOKEN__",
                # Common weak tokens
                "0",
                "1",
                "csrf",
                "token",
                "test",
            ],
            PayloadStage.EXPLOIT: [
                # Token from different session
                "__OTHER_SESSION_TOKEN__",
                # Older token (if time-based)
                "__OLD_TOKEN__",
                # Token for different action
                "__WRONG_ACTION_TOKEN__",
            ],
            PayloadStage.BYPASS: [
                # Case variations
                "__UPPERCASE_TOKEN__",
                "__LOWERCASE_TOKEN__",
                # Content-type bypass
                "__CHANGE_CONTENT_TYPE__",
                # Method override
                "__METHOD_OVERRIDE__",
            ],
        }

    def get_detection_patterns(self) -> List[Pattern]:
        """Return patterns that indicate CSRF vulnerability."""
        patterns = [
            # Action completed without token
            r"success",
            r"updated",
            r"deleted",
            r"created",
            r"saved",
            r"submitted",
            r"completed",
            r"confirmed",
            # Redirect after action
            r"302 Found",
            r"location:",
            r"redirect",
            # Missing token errors (indicates token expected)
            r"csrf.*token.*missing",
            r"token.*required",
            r"invalid.*token",
            r"csrf.*validation.*failed",
            # Specific framework messages
            r"Forbidden.*CSRF",
            r"CSRF.*verification.*failed",
        ]
        return [re.compile(p, re.IGNORECASE) for p in patterns]

    async def perceive(self):
        """
        Override perception for CSRF-specific analysis.

        CSRF testing requires comparing requests with and without tokens.
        """
        perception = await super().perceive()

        if perception:
            # Additional CSRF-specific analysis
            # Check for anti-CSRF tokens in response forms
            token_patterns = [
                r'name=["\']?csrf[_-]?token["\']?',
                r'name=["\']?_token["\']?',
                r'name=["\']?authenticity_token["\']?',
                r'name=["\']?__RequestVerificationToken["\']?',
                r'X-CSRF-TOKEN',
                r'X-XSRF-TOKEN',
            ]

            for pattern in token_patterns:
                if re.search(pattern, perception.response_body, re.IGNORECASE):
                    perception.error_indicators.append(f"CSRF token found: {pattern}")

            # Check SameSite cookie attribute
            set_cookie = perception.response_headers.get("Set-Cookie", "")
            if "SameSite=None" in set_cookie:
                perception.error_indicators.append("SameSite=None cookie")
            elif "SameSite" not in set_cookie:
                perception.error_indicators.append("Missing SameSite attribute")

        return perception


class CSRFTokenAnalyzer(CSRFAgent):
    """Specialized agent for CSRF token analysis."""

    @property
    def vulnerability_type(self) -> str:
        return "csrf_token"

    async def analyze_token(self, token: str) -> Dict:
        """Analyze CSRF token for weaknesses."""
        analysis = {
            "length": len(token),
            "entropy_estimate": "low" if len(set(token)) < 10 else "medium" if len(set(token)) < 20 else "high",
            "issues": []
        }

        # Check for weak patterns
        if len(token) < 16:
            analysis["issues"].append("Token too short")

        if token.isdigit():
            analysis["issues"].append("Numeric-only token")

        if token.isalpha():
            analysis["issues"].append("Alpha-only token")

        # Check for predictable patterns
        import time
        timestamp_patterns = [
            str(int(time.time()))[:6],
            str(int(time.time() * 1000))[:8],
        ]
        for pattern in timestamp_patterns:
            if pattern in token:
                analysis["issues"].append("Possible timestamp in token")
                break

        # Check for sequential patterns
        if any(str(i) * 3 in token for i in range(10)):
            analysis["issues"].append("Sequential pattern detected")

        return analysis
