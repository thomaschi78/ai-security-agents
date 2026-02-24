"""Priority and chaining rules for vulnerability testing."""

from typing import Dict, List, Set, Tuple
from dataclasses import dataclass, field


@dataclass
class ChainRule:
    """Rule for vulnerability chaining."""
    source_vuln: str
    target_vuln: str
    priority: int  # Higher = more important
    description: str
    conditions: List[str] = field(default_factory=list)


# Agent priority (higher = runs first)
AGENT_PRIORITIES = {
    "cmdi": 10,      # Critical - command execution
    "log4shell": 10, # Critical - RCE
    "sqli": 9,       # Critical - data access
    "ssti": 9,       # High - often leads to RCE
    "xxe": 8,        # High - data disclosure + SSRF
    "lfi": 8,        # High - code execution possible
    "ssrf": 8,       # High - internal access
    "path_traversal": 7,
    "xss": 7,        # Medium-High - client-side
    "csrf": 5,       # Medium
}

# Vulnerability chaining rules
CHAINING_RULES = [
    ChainRule(
        source_vuln="sqli",
        target_vuln="ssrf",
        priority=8,
        description="SQLi can expose internal URLs from database",
        conditions=["Found internal URLs in SQLi output"]
    ),
    ChainRule(
        source_vuln="lfi",
        target_vuln="sqli",
        priority=9,
        description="LFI can expose database credentials in config files",
        conditions=["Read config file with credentials"]
    ),
    ChainRule(
        source_vuln="xxe",
        target_vuln="ssrf",
        priority=8,
        description="XXE can make server-side requests",
        conditions=["XXE external entity processing confirmed"]
    ),
    ChainRule(
        source_vuln="xxe",
        target_vuln="lfi",
        priority=7,
        description="XXE can read local files",
        conditions=["File protocol available in XXE"]
    ),
    ChainRule(
        source_vuln="ssrf",
        target_vuln="cmdi",
        priority=9,
        description="SSRF to internal service with RCE",
        conditions=["Internal service accessible"]
    ),
    ChainRule(
        source_vuln="ssti",
        target_vuln="cmdi",
        priority=10,
        description="SSTI often leads to command execution",
        conditions=["Template engine identified"]
    ),
    ChainRule(
        source_vuln="lfi",
        target_vuln="log4shell",
        priority=7,
        description="LFI can access log files for Log4j poisoning",
        conditions=["Log files accessible"]
    ),
    ChainRule(
        source_vuln="xss",
        target_vuln="csrf",
        priority=6,
        description="XSS can bypass CSRF protections",
        conditions=["Reflected XSS confirmed"]
    ),
]


class PriorityManager:
    """
    Manages agent priorities and chaining logic.

    Features:
    - Agent execution ordering
    - Vulnerability chain detection
    - Dynamic priority adjustment
    """

    def __init__(self):
        self._priorities = AGENT_PRIORITIES.copy()
        self._chain_rules = CHAINING_RULES.copy()
        self._active_chains: Dict[str, List[str]] = {}
        self._completed_vulns: Set[str] = set()

    def get_agent_priority(self, vuln_type: str) -> int:
        """Get priority for an agent type."""
        return self._priorities.get(vuln_type, 5)

    def get_sorted_agents(self, agent_types: List[str]) -> List[str]:
        """Sort agent types by priority (highest first)."""
        return sorted(
            agent_types,
            key=lambda t: self._priorities.get(t, 5),
            reverse=True
        )

    def get_chain_opportunities(self, source_vuln: str) -> List[ChainRule]:
        """Get chaining opportunities from a confirmed vulnerability."""
        return [
            rule for rule in self._chain_rules
            if rule.source_vuln == source_vuln
        ]

    def get_chain_targets(self, source_vuln: str) -> List[Tuple[str, int]]:
        """Get target vulnerability types and priorities for chaining."""
        opportunities = self.get_chain_opportunities(source_vuln)
        return [(rule.target_vuln, rule.priority) for rule in opportunities]

    def record_finding(self, vuln_type: str, finding_id: str) -> List[str]:
        """
        Record a confirmed finding and return suggested chain targets.

        Args:
            vuln_type: Type of vulnerability found
            finding_id: ID of the finding

        Returns:
            List of vulnerability types to chain to
        """
        self._completed_vulns.add(vuln_type)

        # Get chain opportunities
        chain_targets = []
        for rule in self.get_chain_opportunities(vuln_type):
            if rule.target_vuln not in self._completed_vulns:
                chain_targets.append(rule.target_vuln)
                self._active_chains.setdefault(finding_id, []).append(rule.target_vuln)

        return chain_targets

    def adjust_priority(self, vuln_type: str, adjustment: int) -> None:
        """Dynamically adjust an agent's priority."""
        current = self._priorities.get(vuln_type, 5)
        self._priorities[vuln_type] = max(1, min(10, current + adjustment))

    def boost_chain_targets(self, source_vuln: str, boost: int = 2) -> None:
        """Boost priority of chain targets when source is confirmed."""
        for rule in self.get_chain_opportunities(source_vuln):
            self.adjust_priority(rule.target_vuln, boost)

    def get_execution_plan(
        self,
        agent_types: List[str],
        parallel_limit: int = 5
    ) -> List[List[str]]:
        """
        Create an execution plan with batches of parallel agents.

        Args:
            agent_types: Types of agents to run
            parallel_limit: Max agents per batch

        Returns:
            List of batches, each batch is a list of agent types
        """
        sorted_agents = self.get_sorted_agents(agent_types)

        # Group by priority level for parallel execution
        batches = []
        current_batch = []
        current_priority = None

        for agent_type in sorted_agents:
            priority = self.get_agent_priority(agent_type)

            if current_priority is None:
                current_priority = priority

            # Start new batch if priority changed or batch full
            if priority != current_priority or len(current_batch) >= parallel_limit:
                if current_batch:
                    batches.append(current_batch)
                current_batch = [agent_type]
                current_priority = priority
            else:
                current_batch.append(agent_type)

        if current_batch:
            batches.append(current_batch)

        return batches

    def get_stats(self) -> Dict:
        """Get priority manager statistics."""
        return {
            "agent_priorities": self._priorities.copy(),
            "chain_rules_count": len(self._chain_rules),
            "completed_vulns": list(self._completed_vulns),
            "active_chains": len(self._active_chains),
        }
