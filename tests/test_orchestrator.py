"""Tests for orchestrator and scheduling."""

import pytest
import asyncio
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).parent.parent / "python"))

# Import individual modules to avoid relative import issues
from orchestrator.scheduler import Scheduler, ExecutionMode, ScheduledTask
from orchestrator.priority_manager import PriorityManager
from results.finding import ScanTarget


class TestExecutionMode:
    """Tests for execution mode enum."""

    def test_all_modes_defined(self):
        """Test all execution modes exist."""
        assert ExecutionMode.PARALLEL
        assert ExecutionMode.SEQUENTIAL
        assert ExecutionMode.ADAPTIVE


class TestScheduler:
    """Tests for task scheduler."""

    @pytest.fixture
    def scheduler(self):
        """Create scheduler for testing."""
        return Scheduler(mode=ExecutionMode.ADAPTIVE, max_concurrent=3)

    def test_add_task(self, scheduler):
        """Test adding tasks to scheduler."""
        task = scheduler.add_task(
            agent_id="sqli_test_1",
            agent_type="sqli",
            target_url="http://example.com",
            target_parameter="id",
            priority=9
        )

        assert task.agent_id == "sqli_test_1"
        assert task.status == "pending"
        assert task.priority == 9

    def test_get_ready_tasks(self, scheduler):
        """Test getting tasks ready for execution."""
        scheduler.add_task(
            agent_id="task_1",
            agent_type="sqli",
            target_url="http://example.com",
            target_parameter="id",
            priority=9
        )
        scheduler.add_task(
            agent_id="task_2",
            agent_type="xss",
            target_url="http://example.com",
            target_parameter="id",
            priority=7
        )

        ready = scheduler.get_ready_tasks()
        assert len(ready) == 2
        # Higher priority first
        assert ready[0].priority >= ready[1].priority

    def test_task_dependencies(self, scheduler):
        """Test task dependency handling."""
        scheduler.add_task(
            agent_id="task_1",
            agent_type="sqli",
            target_url="http://example.com",
            target_parameter="id"
        )
        scheduler.add_task(
            agent_id="task_2",
            agent_type="ssrf",
            target_url="http://example.com",
            target_parameter="id",
            dependencies=["task_1"]
        )

        ready = scheduler.get_ready_tasks()
        # Only task_1 should be ready
        assert len(ready) == 1
        assert ready[0].agent_id == "task_1"


class TestPriorityManager:
    """Tests for priority manager."""

    @pytest.fixture
    def manager(self):
        """Create priority manager for testing."""
        return PriorityManager()

    def test_agent_priorities(self, manager):
        """Test getting agent priorities."""
        # CMDi should be critical priority
        assert manager.get_agent_priority("cmdi") == 10

        # CSRF should be medium priority
        assert manager.get_agent_priority("csrf") == 5

    def test_sorted_agents(self, manager):
        """Test sorting agents by priority."""
        agents = ["xss", "cmdi", "csrf", "sqli"]
        sorted_agents = manager.get_sorted_agents(agents)

        # CMDi should be first (priority 10)
        assert sorted_agents[0] == "cmdi"
        # CSRF should be last (priority 5)
        assert sorted_agents[-1] == "csrf"

    def test_chain_opportunities(self, manager):
        """Test getting chain opportunities."""
        chains = manager.get_chain_opportunities("sqli")

        # SQLi should chain to SSRF
        target_types = [c.target_vuln for c in chains]
        assert "ssrf" in target_types

    def test_record_finding(self, manager):
        """Test recording findings and getting chain targets."""
        targets = manager.record_finding("lfi", "finding_123")

        # LFI should suggest SQLi chaining
        assert "sqli" in targets

    def test_execution_plan(self, manager):
        """Test creating execution plan."""
        agents = ["sqli", "xss", "csrf", "cmdi"]
        plan = manager.get_execution_plan(agents, parallel_limit=2)

        # Should have batches
        assert len(plan) > 0

        # First batch should have high priority agents
        first_batch_types = set(plan[0])
        assert "cmdi" in first_batch_types or "sqli" in first_batch_types


class TestScanTarget:
    """Tests for scan target model."""

    def test_target_creation(self):
        """Test creating scan target."""
        target = ScanTarget(
            url="http://example.com/search",
            parameters=[{"name": "q", "value": "test"}],
            method="GET"
        )

        assert target.url == "http://example.com/search"
        assert len(target.parameters) == 1
        assert target.method == "GET"

    def test_target_to_dict(self):
        """Test serializing scan target."""
        target = ScanTarget(
            url="http://example.com",
            parameters=[{"name": "id", "value": "1"}]
        )

        data = target.to_dict()

        assert data["url"] == "http://example.com"
        assert data["parameters"][0]["name"] == "id"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
