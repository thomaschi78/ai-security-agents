"""Security testing agents package."""

from .base import (
    BaseAgent,
    AgentState,
    PayloadStage,
    AgentContext,
    PerceptionData,
    ReasoningResult,
    ActionResult,
    StageBasedAgentMixin,
)
from .payload import (
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
    AGENT_CLASSES,
    PRIMARY_AGENTS,
    get_agent_class,
    create_agent,
)

__all__ = [
    # Base components
    "BaseAgent",
    "AgentState",
    "PayloadStage",
    "AgentContext",
    "PerceptionData",
    "ReasoningResult",
    "ActionResult",
    "StageBasedAgentMixin",
    # Payload agents
    "SQLiAgent",
    "XSSAgent",
    "CMDiAgent",
    "LFIAgent",
    "SSRFAgent",
    "XXEAgent",
    "Log4ShellAgent",
    "CSRFAgent",
    "SSTIAgent",
    "PathTraversalAgent",
    # Utilities
    "AGENT_CLASSES",
    "PRIMARY_AGENTS",
    "get_agent_class",
    "create_agent",
]
