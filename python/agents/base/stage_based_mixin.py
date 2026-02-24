"""Mixin for staged payload iteration in security agents."""

from abc import abstractmethod
from typing import List, Dict, Any, Optional, Iterator
from .agent_state import PayloadStage


class StageBasedAgentMixin:
    """
    Mixin that provides staged payload iteration capabilities.

    Agents progress through stages:
    1. PROBE: Initial detection with safe payloads
    2. CONFIRM: Verify vulnerability with more targeted payloads
    3. EXPLOIT: Demonstrate impact with exploitation payloads
    4. BYPASS: Attempt WAF/filter evasion techniques
    """

    @property
    @abstractmethod
    def staged_payloads(self) -> Dict[PayloadStage, List[str]]:
        """
        Return payloads organized by stage.

        Returns:
            Dict mapping PayloadStage to list of payloads
        """
        pass

    @property
    def stage_descriptions(self) -> Dict[PayloadStage, str]:
        """Human-readable descriptions of each stage."""
        return {
            PayloadStage.PROBE: "Initial detection probes to identify potential vulnerabilities",
            PayloadStage.CONFIRM: "Confirmation payloads to verify vulnerability exists",
            PayloadStage.EXPLOIT: "Exploitation payloads to demonstrate impact",
            PayloadStage.BYPASS: "Bypass payloads to evade filters and WAFs",
        }

    def get_stage_payloads(self, stage: PayloadStage) -> List[str]:
        """Get payloads for a specific stage."""
        return self.staged_payloads.get(stage, [])

    def get_all_payloads_up_to_stage(self, stage: PayloadStage) -> List[str]:
        """Get all payloads from PROBE up to and including the given stage."""
        payloads = []
        for s in PayloadStage:
            payloads.extend(self.get_stage_payloads(s))
            if s == stage:
                break
        return payloads

    def iterate_staged_payloads(
        self,
        start_stage: PayloadStage = PayloadStage.PROBE,
        max_per_stage: Optional[int] = None
    ) -> Iterator[tuple]:
        """
        Iterate through payloads stage by stage.

        Args:
            start_stage: Stage to start from
            max_per_stage: Maximum payloads to yield per stage

        Yields:
            Tuple of (stage, payload_index, payload)
        """
        started = False
        for stage in PayloadStage:
            if stage == start_stage:
                started = True
            if not started:
                continue

            payloads = self.get_stage_payloads(stage)
            if max_per_stage:
                payloads = payloads[:max_per_stage]

            for idx, payload in enumerate(payloads):
                yield (stage, idx, payload)

    def should_escalate_stage(
        self,
        current_stage: PayloadStage,
        success_indicators: int,
        total_attempts: int,
        confidence: float
    ) -> bool:
        """
        Determine if agent should escalate to next stage.

        Args:
            current_stage: Current payload stage
            success_indicators: Number of potential success indicators found
            total_attempts: Total payloads attempted in current stage
            confidence: Current confidence score (0-1)

        Returns:
            True if should escalate to next stage
        """
        if current_stage == PayloadStage.BYPASS:
            return False  # Already at final stage

        # Escalation thresholds per stage
        thresholds = {
            PayloadStage.PROBE: {"indicators": 1, "confidence": 0.3},
            PayloadStage.CONFIRM: {"indicators": 2, "confidence": 0.6},
            PayloadStage.EXPLOIT: {"indicators": 1, "confidence": 0.8},
        }

        threshold = thresholds.get(current_stage, {"indicators": 1, "confidence": 0.5})

        return (
            success_indicators >= threshold["indicators"] and
            confidence >= threshold["confidence"]
        )

    def get_stage_priority(self, stage: PayloadStage) -> int:
        """Get numeric priority for a stage (higher = more important)."""
        priorities = {
            PayloadStage.PROBE: 1,
            PayloadStage.CONFIRM: 2,
            PayloadStage.EXPLOIT: 3,
            PayloadStage.BYPASS: 4,
        }
        return priorities.get(stage, 0)

    def encode_payload(self, payload: str, encoding: str = "none") -> str:
        """
        Encode payload with specified encoding.

        Args:
            payload: Raw payload string
            encoding: Encoding type (none, url, double_url, unicode, hex, base64)

        Returns:
            Encoded payload
        """
        import urllib.parse
        import base64

        if encoding == "none":
            return payload
        elif encoding == "url":
            return urllib.parse.quote(payload, safe='')
        elif encoding == "double_url":
            return urllib.parse.quote(urllib.parse.quote(payload, safe=''), safe='')
        elif encoding == "unicode":
            return ''.join(f'\\u{ord(c):04x}' for c in payload)
        elif encoding == "hex":
            return ''.join(f'%{ord(c):02x}' for c in payload)
        elif encoding == "base64":
            return base64.b64encode(payload.encode()).decode()
        else:
            return payload

    def get_bypass_encodings(self) -> List[str]:
        """Get list of encodings to try for bypass stage."""
        return [
            "none",
            "url",
            "double_url",
            "unicode",
            "hex",
        ]
