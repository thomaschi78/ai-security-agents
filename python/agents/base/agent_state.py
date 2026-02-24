"""Agent state management for security testing agents."""

from enum import Enum, auto
from dataclasses import dataclass, field
from typing import Any, Optional
from datetime import datetime
import uuid


class AgentState(Enum):
    """States in the agent lifecycle."""
    IDLE = auto()
    PERCEIVING = auto()
    REASONING = auto()
    ACTING = auto()
    WAITING = auto()
    COMPLETED = auto()
    ERROR = auto()
    SUSPENDED = auto()


class PayloadStage(Enum):
    """Stages of payload testing progression."""
    PROBE = auto()      # Initial detection probes
    CONFIRM = auto()    # Confirm vulnerability exists
    EXPLOIT = auto()    # Demonstrate exploitability
    BYPASS = auto()     # WAF/filter bypass attempts


@dataclass
class AgentContext:
    """Context information for agent execution."""
    session_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    correlation_id: Optional[str] = None
    target_url: str = ""
    target_parameter: str = ""
    method: str = "GET"
    headers: dict = field(default_factory=dict)
    cookies: dict = field(default_factory=dict)

    # State tracking
    current_state: AgentState = AgentState.IDLE
    current_stage: PayloadStage = PayloadStage.PROBE

    # Execution tracking
    payloads_tested: int = 0
    findings_count: int = 0
    start_time: Optional[datetime] = None
    last_action_time: Optional[datetime] = None

    # Results
    confirmed_vulnerable: bool = False
    confidence_score: float = 0.0

    def transition_to(self, new_state: AgentState) -> None:
        """Transition to a new state."""
        self.current_state = new_state
        self.last_action_time = datetime.utcnow()

    def advance_stage(self) -> bool:
        """Advance to next payload stage. Returns False if at final stage."""
        stages = list(PayloadStage)
        current_idx = stages.index(self.current_stage)
        if current_idx < len(stages) - 1:
            self.current_stage = stages[current_idx + 1]
            return True
        return False

    def reset_for_new_target(self, url: str, parameter: str) -> None:
        """Reset context for a new target."""
        self.target_url = url
        self.target_parameter = parameter
        self.current_state = AgentState.IDLE
        self.current_stage = PayloadStage.PROBE
        self.payloads_tested = 0
        self.findings_count = 0
        self.confirmed_vulnerable = False
        self.confidence_score = 0.0
        self.start_time = datetime.utcnow()


@dataclass
class PerceptionData:
    """Data gathered during perception phase."""
    response_body: str = ""
    response_headers: dict = field(default_factory=dict)
    status_code: int = 0
    response_time_ms: float = 0.0
    content_type: str = ""
    payload_used: str = ""

    # Analysis hints
    error_indicators: list = field(default_factory=list)
    reflection_points: list = field(default_factory=list)
    timing_anomalies: bool = False


@dataclass
class ReasoningResult:
    """Result from Claude reasoning analysis."""
    decision: str = ""  # CONTINUE, ESCALATE, STOP, REPORT
    confidence: float = 0.0
    reasoning_chain: list = field(default_factory=list)
    next_payloads: list = field(default_factory=list)
    vulnerability_indicators: list = field(default_factory=list)
    recommended_stage: Optional[PayloadStage] = None
    chain_opportunities: list = field(default_factory=list)  # Other vulns to try


@dataclass
class ActionResult:
    """Result from action execution."""
    success: bool = False
    action_type: str = ""  # SEND_PAYLOAD, REPORT_FINDING, CHAIN_AGENT
    payload: str = ""
    response: Optional[PerceptionData] = None
    error: Optional[str] = None
    timestamp: datetime = field(default_factory=datetime.utcnow)
