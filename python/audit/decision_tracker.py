"""Decision tracking for AI reasoning audit."""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional
import uuid
import json


@dataclass
class Decision:
    """Represents a single AI decision."""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = field(default_factory=datetime.utcnow)
    agent_id: str = ""
    decision_type: str = ""  # CONTINUE, ESCALATE, REPORT, STOP, CHAIN
    confidence: float = 0.0
    reasoning_steps: List[str] = field(default_factory=list)
    context: Dict[str, Any] = field(default_factory=dict)
    outcome: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat(),
            "agent_id": self.agent_id,
            "decision_type": self.decision_type,
            "confidence": self.confidence,
            "reasoning_steps": self.reasoning_steps,
            "context": self.context,
            "outcome": self.outcome,
        }


@dataclass
class DecisionChain:
    """Chain of related decisions for a single target."""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    target_url: str = ""
    target_parameter: str = ""
    agent_id: str = ""
    decisions: List[Decision] = field(default_factory=list)
    final_decision: Optional[str] = None
    vulnerability_found: bool = False
    start_time: datetime = field(default_factory=datetime.utcnow)
    end_time: Optional[datetime] = None

    def add_decision(self, decision: Decision) -> None:
        """Add a decision to the chain."""
        self.decisions.append(decision)
        self.final_decision = decision.decision_type

    def close(self, vulnerability_found: bool = False) -> None:
        """Close the decision chain."""
        self.end_time = datetime.utcnow()
        self.vulnerability_found = vulnerability_found

    def get_confidence_progression(self) -> List[float]:
        """Get confidence scores over time."""
        return [d.confidence for d in self.decisions]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "target_url": self.target_url,
            "target_parameter": self.target_parameter,
            "agent_id": self.agent_id,
            "decisions": [d.to_dict() for d in self.decisions],
            "final_decision": self.final_decision,
            "vulnerability_found": self.vulnerability_found,
            "start_time": self.start_time.isoformat(),
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "decision_count": len(self.decisions),
        }


class DecisionTracker:
    """
    Tracks AI decisions for audit and analysis.

    Enables:
    - Decision chain tracking per target
    - Confidence progression analysis
    - Decision pattern identification
    - Audit trail for explainability
    """

    def __init__(self, session_id: Optional[str] = None):
        self.session_id = session_id or str(uuid.uuid4())
        self._chains: Dict[str, DecisionChain] = {}
        self._all_decisions: List[Decision] = []
        self._stats = {
            "total_decisions": 0,
            "report_decisions": 0,
            "escalate_decisions": 0,
            "continue_decisions": 0,
            "stop_decisions": 0,
            "chain_decisions": 0,
        }

    def start_chain(
        self,
        agent_id: str,
        target_url: str,
        target_parameter: str
    ) -> str:
        """Start a new decision chain for a target."""
        chain = DecisionChain(
            agent_id=agent_id,
            target_url=target_url,
            target_parameter=target_parameter
        )
        self._chains[chain.id] = chain
        return chain.id

    def record_decision(
        self,
        chain_id: str,
        decision_type: str,
        confidence: float,
        reasoning_steps: List[str],
        context: Optional[Dict[str, Any]] = None
    ) -> Decision:
        """Record a decision in a chain."""
        decision = Decision(
            agent_id=self._chains[chain_id].agent_id if chain_id in self._chains else "",
            decision_type=decision_type,
            confidence=confidence,
            reasoning_steps=reasoning_steps,
            context=context or {},
        )

        if chain_id in self._chains:
            self._chains[chain_id].add_decision(decision)

        self._all_decisions.append(decision)
        self._stats["total_decisions"] += 1

        # Update type-specific stats
        stat_key = f"{decision_type.lower()}_decisions"
        if stat_key in self._stats:
            self._stats[stat_key] += 1

        return decision

    def close_chain(self, chain_id: str, vulnerability_found: bool = False) -> Optional[DecisionChain]:
        """Close a decision chain."""
        if chain_id in self._chains:
            chain = self._chains[chain_id]
            chain.close(vulnerability_found)
            return chain
        return None

    def get_chain(self, chain_id: str) -> Optional[DecisionChain]:
        """Get a decision chain by ID."""
        return self._chains.get(chain_id)

    def get_chains_for_agent(self, agent_id: str) -> List[DecisionChain]:
        """Get all chains for an agent."""
        return [c for c in self._chains.values() if c.agent_id == agent_id]

    def get_chains_with_findings(self) -> List[DecisionChain]:
        """Get chains that resulted in vulnerability findings."""
        return [c for c in self._chains.values() if c.vulnerability_found]

    def analyze_decision_patterns(self) -> Dict[str, Any]:
        """Analyze patterns in decisions."""
        if not self._all_decisions:
            return {"error": "No decisions to analyze"}

        confidences = [d.confidence for d in self._all_decisions]
        decisions_by_type = {}
        for d in self._all_decisions:
            decisions_by_type.setdefault(d.decision_type, []).append(d)

        return {
            "total_decisions": len(self._all_decisions),
            "avg_confidence": sum(confidences) / len(confidences),
            "max_confidence": max(confidences),
            "min_confidence": min(confidences),
            "decisions_by_type": {k: len(v) for k, v in decisions_by_type.items()},
            "report_rate": self._stats["report_decisions"] / len(self._all_decisions)
            if self._all_decisions else 0,
        }

    def get_stats(self) -> Dict[str, Any]:
        """Get tracking statistics."""
        return {
            **self._stats,
            "active_chains": len([c for c in self._chains.values() if c.end_time is None]),
            "completed_chains": len([c for c in self._chains.values() if c.end_time is not None]),
            "chains_with_findings": len(self.get_chains_with_findings()),
        }

    def export_to_json(self, filepath: str) -> None:
        """Export all tracking data to JSON."""
        data = {
            "session_id": self.session_id,
            "export_time": datetime.utcnow().isoformat(),
            "stats": self.get_stats(),
            "analysis": self.analyze_decision_patterns(),
            "chains": [c.to_dict() for c in self._chains.values()],
        }

        with open(filepath, "w") as f:
            json.dump(data, f, indent=2)
