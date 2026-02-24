"""Base agent class implementing Perception-Reasoning-Action loop."""

from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional, Pattern
import asyncio
import re
import uuid
from datetime import datetime

from .agent_state import (
    AgentState, PayloadStage, AgentContext,
    PerceptionData, ReasoningResult, ActionResult
)
from .stage_based_mixin import StageBasedAgentMixin


class BaseAgent(ABC, StageBasedAgentMixin):
    """
    Base class for all security testing agents.

    Implements the Perception-Reasoning-Action (PRA) loop:
    1. Perceive: Gather data from target response
    2. Reason: Use Claude to analyze and decide next action
    3. Act: Execute the decided action
    """

    def __init__(
        self,
        agent_id: Optional[str] = None,
        claude_client: Any = None,
        http_client: Any = None,
        message_bus: Any = None,
        audit_logger: Any = None,
        config: Optional[Dict[str, Any]] = None
    ):
        self.agent_id = agent_id or f"{self.vulnerability_type}_{uuid.uuid4().hex[:8]}"
        self.claude_client = claude_client
        self.http_client = http_client
        self.message_bus = message_bus
        self.audit_logger = audit_logger
        self.config = config or {}

        self.context = AgentContext()
        self._findings: List[Dict[str, Any]] = []
        self._running = False

    @property
    @abstractmethod
    def vulnerability_type(self) -> str:
        """Return the vulnerability type identifier (e.g., 'sqli', 'xss')."""
        pass

    @property
    @abstractmethod
    def cweid(self) -> int:
        """Return the CWE ID for this vulnerability type."""
        pass

    @property
    @abstractmethod
    def staged_payloads(self) -> Dict[PayloadStage, List[str]]:
        """Return payloads organized by stage."""
        pass

    @abstractmethod
    def get_detection_patterns(self) -> List[Pattern]:
        """Return compiled regex patterns for detecting vulnerability indicators."""
        pass

    @property
    def display_name(self) -> str:
        """Human-readable name for this agent."""
        return f"{self.vulnerability_type.upper()} Agent"

    @property
    def priority(self) -> int:
        """Agent priority (higher = runs first). Override in subclasses."""
        return 5  # Default medium priority

    async def scan(
        self,
        url: str,
        parameter: str,
        method: str = "GET",
        headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None,
        max_payloads: Optional[int] = None
    ) -> List[Dict[str, Any]]:
        """
        Execute a complete scan against a target parameter.

        Args:
            url: Target URL
            parameter: Parameter name to test
            method: HTTP method
            headers: Additional headers
            cookies: Cookies to send
            max_payloads: Maximum payloads to test (None = all)

        Returns:
            List of findings
        """
        self._running = True
        self._findings = []

        # Initialize context
        self.context.reset_for_new_target(url, parameter)
        self.context.method = method
        self.context.headers = headers or {}
        self.context.cookies = cookies or {}

        await self._log_scan_start()

        try:
            # Run PRA loop
            while self._running and self.context.current_state != AgentState.COMPLETED:
                # Check payload limit
                if max_payloads and self.context.payloads_tested >= max_payloads:
                    break

                # Perception phase
                self.context.transition_to(AgentState.PERCEIVING)
                perception = await self.perceive()

                if perception is None:
                    break

                # Reasoning phase
                self.context.transition_to(AgentState.REASONING)
                reasoning = await self.reason(perception)

                # Action phase
                self.context.transition_to(AgentState.ACTING)
                action_result = await self.act(reasoning)

                # Update context based on results
                await self._update_context(reasoning, action_result)

        except Exception as e:
            self.context.transition_to(AgentState.ERROR)
            await self._log_error(str(e))
            raise
        finally:
            self.context.transition_to(AgentState.COMPLETED)
            await self._log_scan_complete()

        return self._findings

    async def perceive(self) -> Optional[PerceptionData]:
        """
        Perception phase: Gather data from the target.

        Returns:
            PerceptionData or None if no more payloads
        """
        # Get next payload based on current stage
        payload = self._get_next_payload()
        if payload is None:
            return None

        # Send request with payload
        perception = PerceptionData(payload_used=payload)

        try:
            response = await self._send_payload(payload)
            perception.response_body = response.get("body", "")
            perception.response_headers = response.get("headers", {})
            perception.status_code = response.get("status_code", 0)
            perception.response_time_ms = response.get("time_ms", 0)
            perception.content_type = response.get("content_type", "")

            # Analyze response for indicators
            perception.error_indicators = self._find_error_indicators(perception)
            perception.reflection_points = self._find_reflections(payload, perception)

            self.context.payloads_tested += 1

        except Exception as e:
            await self._log_error(f"Perception failed: {e}")
            perception.error_indicators = [str(e)]

        await self._log_perception(perception)
        return perception

    async def reason(self, perception: PerceptionData) -> ReasoningResult:
        """
        Reasoning phase: Analyze perception data using Claude.

        Args:
            perception: Data from perception phase

        Returns:
            ReasoningResult with decision and analysis
        """
        result = ReasoningResult()

        # Check detection patterns first
        pattern_matches = self._check_detection_patterns(perception)

        if self.claude_client:
            # Use Claude for advanced reasoning
            try:
                claude_response = await self.claude_client.analyze_response(
                    vulnerability_type=self.vulnerability_type,
                    payload=perception.payload_used,
                    response_body=perception.response_body,
                    status_code=perception.status_code,
                    error_indicators=perception.error_indicators,
                    pattern_matches=pattern_matches,
                    current_stage=self.context.current_stage.name,
                    context={
                        "url": self.context.target_url,
                        "parameter": self.context.target_parameter,
                        "payloads_tested": self.context.payloads_tested,
                    }
                )

                result.decision = claude_response.get("decision", "CONTINUE")
                result.confidence = claude_response.get("confidence", 0.0)
                result.reasoning_chain = claude_response.get("reasoning", [])
                result.next_payloads = claude_response.get("suggested_payloads", [])
                result.vulnerability_indicators = claude_response.get("indicators", [])
                result.chain_opportunities = claude_response.get("chain_opportunities", [])

            except Exception as e:
                await self._log_error(f"Claude reasoning failed: {e}")
                # Fall back to pattern-based reasoning
                result = self._pattern_based_reasoning(perception, pattern_matches)
        else:
            # Pattern-based reasoning without Claude
            result = self._pattern_based_reasoning(perception, pattern_matches)

        await self._log_reasoning(result)
        return result

    async def act(self, reasoning: ReasoningResult) -> ActionResult:
        """
        Action phase: Execute decision from reasoning.

        Args:
            reasoning: Result from reasoning phase

        Returns:
            ActionResult
        """
        result = ActionResult()

        if reasoning.decision == "REPORT":
            # Report a finding
            result = await self._report_finding(reasoning)

        elif reasoning.decision == "ESCALATE":
            # Move to next stage
            if self.context.advance_stage():
                result.success = True
                result.action_type = "STAGE_ESCALATION"
                await self._publish_message("scan_progress", {
                    "agent_id": self.agent_id,
                    "event": "stage_escalation",
                    "new_stage": self.context.current_stage.name
                })
            else:
                result.action_type = "MAX_STAGE_REACHED"

        elif reasoning.decision == "CHAIN":
            # Trigger another agent for chained vulnerability
            result = await self._trigger_chain(reasoning.chain_opportunities)

        elif reasoning.decision == "STOP":
            # Stop scanning this target
            self._running = False
            result.success = True
            result.action_type = "SCAN_STOPPED"

        else:  # CONTINUE
            result.success = True
            result.action_type = "CONTINUE"

        await self._log_action(result)
        return result

    def _get_next_payload(self) -> Optional[str]:
        """Get the next payload to test."""
        payloads = self.get_stage_payloads(self.context.current_stage)

        # Calculate index within current stage
        stage_idx = list(PayloadStage).index(self.context.current_stage)
        payloads_before = sum(
            len(self.get_stage_payloads(s))
            for s in list(PayloadStage)[:stage_idx]
        )

        local_idx = self.context.payloads_tested - payloads_before

        if local_idx < len(payloads):
            return payloads[local_idx]

        # Try to advance to next stage
        if self.context.advance_stage():
            return self.get_stage_payloads(self.context.current_stage)[0] if self.get_stage_payloads(self.context.current_stage) else None

        return None

    async def _send_payload(self, payload: str) -> Dict[str, Any]:
        """Send HTTP request with payload."""
        if self.http_client:
            return await self.http_client.send_request(
                url=self.context.target_url,
                method=self.context.method,
                parameter=self.context.target_parameter,
                payload=payload,
                headers=self.context.headers,
                cookies=self.context.cookies
            )

        # Simulated response for testing without HTTP client
        return {
            "body": "",
            "headers": {},
            "status_code": 200,
            "time_ms": 0,
            "content_type": "text/html"
        }

    def _find_error_indicators(self, perception: PerceptionData) -> List[str]:
        """Find error messages in response."""
        indicators = []
        error_patterns = [
            r"error",
            r"exception",
            r"warning",
            r"syntax",
            r"unexpected",
            r"invalid",
        ]

        body_lower = perception.response_body.lower()
        for pattern in error_patterns:
            if re.search(pattern, body_lower):
                indicators.append(pattern)

        return indicators

    def _find_reflections(self, payload: str, perception: PerceptionData) -> List[str]:
        """Find payload reflections in response."""
        reflections = []

        # Check for exact reflection
        if payload in perception.response_body:
            reflections.append("exact")

        # Check for partial reflections
        for part in payload.split():
            if len(part) > 3 and part in perception.response_body:
                reflections.append(f"partial:{part}")

        return reflections

    def _check_detection_patterns(self, perception: PerceptionData) -> List[Dict[str, Any]]:
        """Check response against detection patterns."""
        matches = []

        for pattern in self.get_detection_patterns():
            match = pattern.search(perception.response_body)
            if match:
                matches.append({
                    "pattern": pattern.pattern,
                    "match": match.group(0)[:100],  # Limit match length
                    "position": match.start()
                })

        return matches

    def _pattern_based_reasoning(
        self,
        perception: PerceptionData,
        pattern_matches: List[Dict[str, Any]]
    ) -> ReasoningResult:
        """Fallback reasoning based on pattern matching."""
        result = ReasoningResult()

        # Calculate confidence based on indicators
        confidence = 0.0

        if pattern_matches:
            confidence += 0.3 * len(pattern_matches)
        if perception.error_indicators:
            confidence += 0.1 * len(perception.error_indicators)
        if perception.reflection_points:
            confidence += 0.2 * len(perception.reflection_points)

        result.confidence = min(confidence, 1.0)
        result.vulnerability_indicators = [m["match"] for m in pattern_matches]

        # Decide next action
        if result.confidence >= 0.7:
            result.decision = "REPORT"
        elif result.confidence >= 0.4 and self.context.current_stage != PayloadStage.BYPASS:
            result.decision = "ESCALATE"
        elif self.context.payloads_tested >= 50:
            result.decision = "STOP"
        else:
            result.decision = "CONTINUE"

        result.reasoning_chain = [
            f"Pattern matches: {len(pattern_matches)}",
            f"Error indicators: {len(perception.error_indicators)}",
            f"Reflections: {len(perception.reflection_points)}",
            f"Confidence: {result.confidence:.2f}",
            f"Decision: {result.decision}"
        ]

        return result

    async def _report_finding(self, reasoning: ReasoningResult) -> ActionResult:
        """Report a vulnerability finding."""
        finding = {
            "id": str(uuid.uuid4()),
            "agent_id": self.agent_id,
            "vulnerability_type": self.vulnerability_type,
            "cweid": self.cweid,
            "url": self.context.target_url,
            "parameter": self.context.target_parameter,
            "method": self.context.method,
            "confidence": reasoning.confidence,
            "stage": self.context.current_stage.name,
            "indicators": reasoning.vulnerability_indicators,
            "reasoning": reasoning.reasoning_chain,
            "timestamp": datetime.utcnow().isoformat(),
        }

        self._findings.append(finding)
        self.context.findings_count += 1
        self.context.confirmed_vulnerable = reasoning.confidence >= 0.8
        self.context.confidence_score = reasoning.confidence

        # Publish finding to message bus
        await self._publish_message("vulnerability_found", finding)

        return ActionResult(
            success=True,
            action_type="REPORT_FINDING",
            payload=str(finding)
        )

    async def _trigger_chain(self, opportunities: List[str]) -> ActionResult:
        """Trigger chained vulnerability testing."""
        if not opportunities:
            return ActionResult(success=False, action_type="NO_CHAIN_OPPORTUNITIES")

        for vuln_type in opportunities:
            await self._publish_message("chain_opportunity", {
                "source_agent": self.agent_id,
                "source_vuln": self.vulnerability_type,
                "target_vuln": vuln_type,
                "context": {
                    "url": self.context.target_url,
                    "parameter": self.context.target_parameter,
                    "evidence": self._findings[-1] if self._findings else None
                }
            })

        return ActionResult(
            success=True,
            action_type="CHAIN_TRIGGERED",
            payload=str(opportunities)
        )

    async def _publish_message(self, topic: str, data: Dict[str, Any]) -> None:
        """Publish message to message bus."""
        if self.message_bus:
            await self.message_bus.publish(topic, {
                "source": self.agent_id,
                "timestamp": datetime.utcnow().isoformat(),
                "data": data
            })

    async def _log_scan_start(self) -> None:
        """Log scan start."""
        if self.audit_logger:
            await self.audit_logger.log_action({
                "type": "scan_start",
                "agent_id": self.agent_id,
                "target": self.context.target_url,
                "parameter": self.context.target_parameter,
                "session_id": self.context.session_id,
            })

    async def _log_scan_complete(self) -> None:
        """Log scan completion."""
        if self.audit_logger:
            await self.audit_logger.log_action({
                "type": "scan_complete",
                "agent_id": self.agent_id,
                "payloads_tested": self.context.payloads_tested,
                "findings": len(self._findings),
                "session_id": self.context.session_id,
            })

    async def _log_perception(self, perception: PerceptionData) -> None:
        """Log perception data."""
        if self.audit_logger:
            await self.audit_logger.log_perception({
                "agent_id": self.agent_id,
                "payload": perception.payload_used,
                "status_code": perception.status_code,
                "indicators": perception.error_indicators,
                "reflections": perception.reflection_points,
                "session_id": self.context.session_id,
            })

    async def _log_reasoning(self, reasoning: ReasoningResult) -> None:
        """Log reasoning result."""
        if self.audit_logger:
            await self.audit_logger.log_reasoning({
                "agent_id": self.agent_id,
                "decision": reasoning.decision,
                "confidence": reasoning.confidence,
                "reasoning_chain": reasoning.reasoning_chain,
                "session_id": self.context.session_id,
            })

    async def _log_action(self, action: ActionResult) -> None:
        """Log action result."""
        if self.audit_logger:
            await self.audit_logger.log_action({
                "agent_id": self.agent_id,
                "action_type": action.action_type,
                "success": action.success,
                "session_id": self.context.session_id,
            })

    async def _log_error(self, error: str) -> None:
        """Log error."""
        if self.audit_logger:
            await self.audit_logger.log_error({
                "agent_id": self.agent_id,
                "error": error,
                "session_id": self.context.session_id,
            })

    def stop(self) -> None:
        """Stop the agent."""
        self._running = False
