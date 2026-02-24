"""Orchestrator components for agent coordination."""

# Import modules that don't have cross-package dependencies directly
from .scheduler import Scheduler, ExecutionMode, ScheduledTask
from .priority_manager import PriorityManager, ChainRule, AGENT_PRIORITIES, CHAINING_RULES

# Lazy import for Orchestrator to avoid circular/relative import issues
# when importing submodules directly
def __getattr__(name):
    if name == "Orchestrator":
        from .orchestrator import Orchestrator
        return Orchestrator
    if name == "OrchestratorConfig":
        from .orchestrator import OrchestratorConfig
        return OrchestratorConfig
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

__all__ = [
    "Orchestrator",
    "OrchestratorConfig",
    "Scheduler",
    "ExecutionMode",
    "ScheduledTask",
    "PriorityManager",
    "ChainRule",
    "AGENT_PRIORITIES",
    "CHAINING_RULES",
]
