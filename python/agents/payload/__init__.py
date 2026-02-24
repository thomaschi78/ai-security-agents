"""Payload agents for various vulnerability types."""

from .sqli_agent import SQLiAgent, SQLiErrorBasedAgent, SQLiTimeBasedAgent
from .xss_agent import XSSAgent, XSSReflectedAgent, XSSDOMAgent
from .cmdi_agent import CMDiAgent, CMDiBlindAgent
from .lfi_agent import LFIAgent, LFIPHPWrapperAgent
from .ssrf_agent import SSRFAgent, SSRFBlindAgent
from .xxe_agent import XXEAgent, XXEBlindAgent
from .log4shell_agent import Log4ShellAgent, Log4Shell2Agent
from .csrf_agent import CSRFAgent, CSRFTokenAnalyzer
from .ssti_agent import SSTIAgent, SSTIJinja2Agent, SSTIFreemarkerAgent
from .path_traversal_agent import PathTraversalAgent, PathTraversalAbsoluteAgent

# All available agent classes
AGENT_CLASSES = {
    "sqli": SQLiAgent,
    "sqli_error": SQLiErrorBasedAgent,
    "sqli_time": SQLiTimeBasedAgent,
    "xss": XSSAgent,
    "xss_reflected": XSSReflectedAgent,
    "xss_dom": XSSDOMAgent,
    "cmdi": CMDiAgent,
    "cmdi_blind": CMDiBlindAgent,
    "lfi": LFIAgent,
    "lfi_php_wrapper": LFIPHPWrapperAgent,
    "ssrf": SSRFAgent,
    "ssrf_blind": SSRFBlindAgent,
    "xxe": XXEAgent,
    "xxe_blind": XXEBlindAgent,
    "log4shell": Log4ShellAgent,
    "log4shell2": Log4Shell2Agent,
    "csrf": CSRFAgent,
    "csrf_token": CSRFTokenAnalyzer,
    "ssti": SSTIAgent,
    "ssti_jinja2": SSTIJinja2Agent,
    "ssti_freemarker": SSTIFreemarkerAgent,
    "path_traversal": PathTraversalAgent,
    "path_traversal_absolute": PathTraversalAbsoluteAgent,
}

# Primary agents (one per vulnerability type)
PRIMARY_AGENTS = [
    SQLiAgent,
    XSSAgent,
    CMDiAgent,
    LFIAgent,
    SSRFAgent,
    XXEAgent,
    Log4ShellAgent,
    CSRFAgent,
    SSTIAgent,
    PathTraversalAgent,
]


def get_agent_class(vulnerability_type: str):
    """Get agent class by vulnerability type."""
    return AGENT_CLASSES.get(vulnerability_type)


def create_agent(vulnerability_type: str, **kwargs):
    """Create an agent instance by vulnerability type."""
    agent_class = get_agent_class(vulnerability_type)
    if agent_class:
        return agent_class(**kwargs)
    raise ValueError(f"Unknown vulnerability type: {vulnerability_type}")


__all__ = [
    "SQLiAgent",
    "SQLiErrorBasedAgent",
    "SQLiTimeBasedAgent",
    "XSSAgent",
    "XSSReflectedAgent",
    "XSSDOMAgent",
    "CMDiAgent",
    "CMDiBlindAgent",
    "LFIAgent",
    "LFIPHPWrapperAgent",
    "SSRFAgent",
    "SSRFBlindAgent",
    "XXEAgent",
    "XXEBlindAgent",
    "Log4ShellAgent",
    "Log4Shell2Agent",
    "CSRFAgent",
    "CSRFTokenAnalyzer",
    "SSTIAgent",
    "SSTIJinja2Agent",
    "SSTIFreemarkerAgent",
    "PathTraversalAgent",
    "PathTraversalAbsoluteAgent",
    "AGENT_CLASSES",
    "PRIMARY_AGENTS",
    "get_agent_class",
    "create_agent",
]
