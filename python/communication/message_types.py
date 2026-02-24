"""Message type definitions for inter-agent communication."""

from enum import Enum, auto
from dataclasses import dataclass, field
from typing import Any, Dict, Optional, List
from datetime import datetime
import uuid


class MessagePriority(Enum):
    """Message priority levels."""
    LOW = 1
    NORMAL = 5
    HIGH = 8
    CRITICAL = 10


class MessageType(Enum):
    """Types of messages in the system."""
    # Scan lifecycle
    SCAN_STARTED = auto()
    SCAN_PROGRESS = auto()
    SCAN_COMPLETED = auto()
    SCAN_ERROR = auto()

    # Vulnerability events
    VULNERABILITY_FOUND = auto()
    VULNERABILITY_CONFIRMED = auto()
    CHAIN_OPPORTUNITY = auto()

    # Agent coordination
    AGENT_STARTED = auto()
    AGENT_STOPPED = auto()
    AGENT_STATE_CHANGE = auto()

    # Orchestrator commands
    START_AGENT = auto()
    STOP_AGENT = auto()
    PAUSE_AGENT = auto()
    RESUME_AGENT = auto()

    # System
    HEARTBEAT = auto()
    SHUTDOWN = auto()


@dataclass
class Message:
    """Base message class for inter-agent communication."""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    type: MessageType = MessageType.SCAN_PROGRESS
    topic: str = ""
    source: str = ""
    timestamp: datetime = field(default_factory=datetime.utcnow)
    priority: MessagePriority = MessagePriority.NORMAL
    correlation_id: Optional[str] = None
    payload: Dict[str, Any] = field(default_factory=dict)

    # Routing
    target_agent: Optional[str] = None  # Specific agent ID, or None for broadcast

    def to_dict(self) -> Dict[str, Any]:
        """Convert message to dictionary."""
        return {
            "id": self.id,
            "type": self.type.name,
            "topic": self.topic,
            "source": self.source,
            "timestamp": self.timestamp.isoformat(),
            "priority": self.priority.name,
            "correlation_id": self.correlation_id,
            "payload": self.payload,
            "target_agent": self.target_agent,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Message":
        """Create message from dictionary."""
        return cls(
            id=data.get("id", str(uuid.uuid4())),
            type=MessageType[data.get("type", "SCAN_PROGRESS")],
            topic=data.get("topic", ""),
            source=data.get("source", ""),
            timestamp=datetime.fromisoformat(data["timestamp"]) if "timestamp" in data else datetime.utcnow(),
            priority=MessagePriority[data.get("priority", "NORMAL")],
            correlation_id=data.get("correlation_id"),
            payload=data.get("payload", {}),
            target_agent=data.get("target_agent"),
        )


@dataclass
class VulnerabilityMessage(Message):
    """Message for vulnerability findings."""
    vulnerability_type: str = ""
    cweid: int = 0
    confidence: float = 0.0
    url: str = ""
    parameter: str = ""

    def __post_init__(self):
        self.type = MessageType.VULNERABILITY_FOUND
        self.topic = "vulnerability_found"
        self.priority = MessagePriority.HIGH


@dataclass
class ChainOpportunityMessage(Message):
    """Message for vulnerability chaining opportunities."""
    source_vuln: str = ""
    target_vuln: str = ""
    chain_context: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        self.type = MessageType.CHAIN_OPPORTUNITY
        self.topic = "chain_opportunity"
        self.priority = MessagePriority.HIGH


@dataclass
class AgentStateMessage(Message):
    """Message for agent state changes."""
    agent_id: str = ""
    previous_state: str = ""
    new_state: str = ""

    def __post_init__(self):
        self.type = MessageType.AGENT_STATE_CHANGE
        self.topic = "agent_state"


@dataclass
class ScanProgressMessage(Message):
    """Message for scan progress updates."""
    agent_id: str = ""
    payloads_tested: int = 0
    findings_count: int = 0
    current_stage: str = ""
    progress_percent: float = 0.0

    def __post_init__(self):
        self.type = MessageType.SCAN_PROGRESS
        self.topic = "scan_progress"


# Topic constants
TOPICS = {
    "vulnerability_found": "Vulnerability detection events",
    "chain_opportunity": "Chaining opportunities between vulnerabilities",
    "scan_progress": "Scan progress updates",
    "agent_state": "Agent lifecycle events",
    "orchestrator": "Orchestrator commands",
    "system": "System-level events",
}


def get_topic_pattern(pattern: str) -> str:
    """
    Convert wildcard pattern to regex for topic matching.

    Examples:
        "vulnerability_*" -> matches vulnerability_found, vulnerability_confirmed
        "*_progress" -> matches scan_progress
        "*" -> matches all topics
    """
    import re
    regex = pattern.replace("*", ".*")
    return f"^{regex}$"
