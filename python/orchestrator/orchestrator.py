"""Main orchestrator for coordinating security agents."""

import asyncio
import logging
from typing import Any, Dict, List, Optional, Type
from datetime import datetime
import uuid

from .scheduler import Scheduler, ExecutionMode, ScheduledTask
from .priority_manager import PriorityManager
from ..agents.base import BaseAgent, AgentState
from ..agents.payload import AGENT_CLASSES, PRIMARY_AGENTS, create_agent
from ..communication import MessageBus, Message
from ..reasoning import ClaudeClient, MockClaudeClient
from ..audit import AuditLogger, DecisionTracker
from ..results import ResultAggregator, ScanResult, ScanTarget, Vulnerability

logger = logging.getLogger(__name__)


class OrchestratorConfig:
    """Configuration for the orchestrator."""

    def __init__(
        self,
        mode: ExecutionMode = ExecutionMode.ADAPTIVE,
        max_concurrent_agents: int = 5,
        enable_chaining: bool = True,
        max_payloads_per_agent: int = 100,
        timeout_per_agent: float = 300.0,
        claude_api_key: Optional[str] = None,
        use_mock_claude: bool = False,
        log_dir: Optional[str] = None,
        agent_types: Optional[List[str]] = None,
    ):
        self.mode = mode
        self.max_concurrent_agents = max_concurrent_agents
        self.enable_chaining = enable_chaining
        self.max_payloads_per_agent = max_payloads_per_agent
        self.timeout_per_agent = timeout_per_agent
        self.claude_api_key = claude_api_key
        self.use_mock_claude = use_mock_claude
        self.log_dir = log_dir
        self.agent_types = agent_types or list(AGENT_CLASSES.keys())


class Orchestrator:
    """
    Main coordinator for security testing agents.

    Handles:
    - Agent lifecycle management
    - Execution scheduling
    - Message bus coordination
    - Result aggregation
    - Vulnerability chaining
    """

    def __init__(self, config: Optional[OrchestratorConfig] = None):
        self.config = config or OrchestratorConfig()
        self.session_id = str(uuid.uuid4())

        # Core components
        self._scheduler = Scheduler(
            mode=self.config.mode,
            max_concurrent=self.config.max_concurrent_agents,
            timeout_per_agent=self.config.timeout_per_agent
        )
        self._priority_manager = PriorityManager()
        self._message_bus = MessageBus()
        self._aggregator = ResultAggregator()
        self._decision_tracker = DecisionTracker(session_id=self.session_id)

        # Audit logger
        self._audit_logger = AuditLogger(
            log_dir=self.config.log_dir,
            session_id=self.session_id,
            console_output=True
        )

        # Claude client
        if self.config.use_mock_claude:
            self._claude_client = MockClaudeClient()
        elif self.config.claude_api_key:
            self._claude_client = ClaudeClient(api_key=self.config.claude_api_key)
        else:
            self._claude_client = None

        # Active agents
        self._agents: Dict[str, BaseAgent] = {}
        self._running = False

    async def scan(
        self,
        target: ScanTarget,
        agent_types: Optional[List[str]] = None
    ) -> ScanResult:
        """
        Execute a complete scan against a target.

        Args:
            target: Scan target configuration
            agent_types: Specific agent types to use (default: all primary)

        Returns:
            ScanResult with all findings
        """
        self._running = True
        start_time = datetime.utcnow()

        # Determine which agents to use
        types_to_use = agent_types or [a.__name__.lower().replace("agent", "")
                                       for a in PRIMARY_AGENTS]
        # Filter to valid types
        types_to_use = [t for t in types_to_use if t in AGENT_CLASSES]

        await self._audit_logger.start_session({
            "target": target.to_dict(),
            "agent_types": types_to_use,
            "config": {
                "mode": self.config.mode.name,
                "max_concurrent": self.config.max_concurrent_agents,
                "enable_chaining": self.config.enable_chaining,
            }
        })

        try:
            # Start message bus
            await self._message_bus.start()

            # Subscribe to events
            self._setup_subscriptions()

            # Create and schedule agents for each parameter
            for param in target.parameters:
                param_name = param.get("name", "")
                await self._schedule_agents_for_parameter(
                    target, param_name, types_to_use
                )

            # Execute all scheduled tasks
            await self._scheduler.run_all(self._execute_agent)

        except Exception as e:
            logger.error(f"Scan error: {e}")
            raise

        finally:
            self._running = False
            await self._message_bus.stop()

        # Create result
        result = self._aggregator.create_scan_result(
            target=target,
            agents_used=types_to_use,
            payloads_tested=sum(
                a.context.payloads_tested for a in self._agents.values()
            ),
            metadata={
                "session_id": self.session_id,
                "scheduler_stats": self._scheduler.get_stats(),
            }
        )

        await self._audit_logger.end_session({
            "findings": result.vulnerability_count,
            "duration": result.duration_seconds,
        })

        return result

    async def _schedule_agents_for_parameter(
        self,
        target: ScanTarget,
        parameter: str,
        agent_types: List[str]
    ) -> None:
        """Schedule agents for a specific parameter."""
        # Get execution plan from priority manager
        execution_plan = self._priority_manager.get_execution_plan(
            agent_types,
            parallel_limit=self.config.max_concurrent_agents
        )

        for batch in execution_plan:
            for agent_type in batch:
                agent_id = f"{agent_type}_{parameter}_{uuid.uuid4().hex[:8]}"

                # Create agent
                agent = create_agent(
                    agent_type,
                    agent_id=agent_id,
                    claude_client=self._claude_client,
                    message_bus=self._message_bus,
                    audit_logger=self._audit_logger,
                )
                self._agents[agent_id] = agent

                # Schedule task
                self._scheduler.add_task(
                    agent_id=agent_id,
                    agent_type=agent_type,
                    target_url=target.url,
                    target_parameter=parameter,
                    priority=self._priority_manager.get_agent_priority(agent_type),
                )

    async def _execute_agent(self, task: ScheduledTask) -> List[Dict[str, Any]]:
        """Execute a single agent task."""
        agent = self._agents.get(task.agent_id)
        if not agent:
            raise ValueError(f"Agent not found: {task.agent_id}")

        await self._audit_logger.log_agent_event(
            "agent_started",
            task.agent_id,
            {"type": task.agent_type, "target": task.target_url}
        )

        try:
            findings = await agent.scan(
                url=task.target_url,
                parameter=task.target_parameter,
                max_payloads=self.config.max_payloads_per_agent,
            )

            # Convert findings to Vulnerability objects and aggregate
            for finding_dict in findings:
                vuln = Vulnerability(
                    id=finding_dict.get("id", str(uuid.uuid4())),
                    vulnerability_type=finding_dict.get("vulnerability_type", ""),
                    cweid=finding_dict.get("cweid", 0),
                    url=finding_dict.get("url", ""),
                    parameter=finding_dict.get("parameter", ""),
                    confidence_score=finding_dict.get("confidence", 0.0),
                    agent_id=task.agent_id,
                    stage=finding_dict.get("stage", ""),
                    reasoning=finding_dict.get("reasoning", []),
                    indicators=finding_dict.get("indicators", []),
                )
                self._aggregator.add_finding(vuln)

                # Handle chaining
                if self.config.enable_chaining:
                    await self._handle_chaining(vuln)

            await self._audit_logger.log_agent_event(
                "agent_completed",
                task.agent_id,
                {"findings": len(findings)}
            )

            return findings

        except Exception as e:
            await self._audit_logger.log_error({
                "agent_id": task.agent_id,
                "error": str(e),
            })
            raise

    async def _handle_chaining(self, vuln: Vulnerability) -> None:
        """Handle vulnerability chaining opportunities."""
        chain_targets = self._priority_manager.record_finding(
            vuln.vulnerability_type,
            vuln.id
        )

        for target_type in chain_targets:
            logger.info(f"Chain opportunity: {vuln.vulnerability_type} -> {target_type}")

            # Publish chain opportunity message
            await self._message_bus.publish(
                "chain_opportunity",
                {
                    "source_vuln": vuln.vulnerability_type,
                    "target_vuln": target_type,
                    "source_finding": vuln.id,
                    "url": vuln.url,
                    "parameter": vuln.parameter,
                },
                source="orchestrator"
            )

            # Optionally schedule additional agents
            self._priority_manager.boost_chain_targets(vuln.vulnerability_type)

    def _setup_subscriptions(self) -> None:
        """Set up message bus subscriptions."""

        async def on_vulnerability_found(msg: Message):
            finding_data = msg.payload.get("data", {})
            await self._audit_logger.log_finding(finding_data)

        async def on_chain_opportunity(msg: Message):
            logger.debug(f"Chain opportunity: {msg.payload}")

        self._message_bus.subscribe(
            "orchestrator",
            "vulnerability_found",
            on_vulnerability_found
        )

        self._message_bus.subscribe(
            "orchestrator",
            "chain_opportunity",
            on_chain_opportunity
        )

    def stop(self) -> None:
        """Stop all scanning."""
        self._running = False
        self._scheduler.stop()
        for agent in self._agents.values():
            agent.stop()

    def get_stats(self) -> Dict[str, Any]:
        """Get orchestrator statistics."""
        return {
            "session_id": self.session_id,
            "running": self._running,
            "agents": len(self._agents),
            "scheduler": self._scheduler.get_stats(),
            "priority_manager": self._priority_manager.get_stats(),
            "aggregator": self._aggregator.get_summary(),
            "message_bus": self._message_bus.get_stats(),
            "audit": self._audit_logger.get_stats(),
        }
