"""Execution scheduling for security agents."""

import asyncio
from enum import Enum, auto
from typing import Any, Callable, Dict, List, Optional, Set
from dataclasses import dataclass, field
from datetime import datetime
import logging

logger = logging.getLogger(__name__)


class ExecutionMode(Enum):
    """Agent execution modes."""
    PARALLEL = auto()    # Run all agents concurrently
    SEQUENTIAL = auto()  # Run agents one at a time
    ADAPTIVE = auto()    # Start parallel, adjust based on findings


@dataclass
class ScheduledTask:
    """A scheduled agent task."""
    agent_id: str
    agent_type: str
    target_url: str
    target_parameter: str
    priority: int = 5
    dependencies: List[str] = field(default_factory=list)
    status: str = "pending"  # pending, running, completed, failed
    result: Any = None
    error: Optional[str] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None


class Scheduler:
    """
    Schedules and coordinates agent execution.

    Features:
    - Multiple execution modes
    - Concurrency control with semaphores
    - Dependency tracking
    - Dynamic rescheduling
    """

    def __init__(
        self,
        mode: ExecutionMode = ExecutionMode.ADAPTIVE,
        max_concurrent: int = 5,
        timeout_per_agent: float = 300.0
    ):
        self.mode = mode
        self.max_concurrent = max_concurrent
        self.timeout_per_agent = timeout_per_agent

        self._tasks: Dict[str, ScheduledTask] = {}
        self._semaphore = asyncio.Semaphore(max_concurrent)
        self._running = False
        self._completed_count = 0
        self._failed_count = 0

    def add_task(
        self,
        agent_id: str,
        agent_type: str,
        target_url: str,
        target_parameter: str,
        priority: int = 5,
        dependencies: Optional[List[str]] = None
    ) -> ScheduledTask:
        """Add a task to the schedule."""
        task = ScheduledTask(
            agent_id=agent_id,
            agent_type=agent_type,
            target_url=target_url,
            target_parameter=target_parameter,
            priority=priority,
            dependencies=dependencies or [],
        )
        self._tasks[agent_id] = task
        return task

    def get_ready_tasks(self) -> List[ScheduledTask]:
        """Get tasks that are ready to run (dependencies met)."""
        ready = []
        for task in self._tasks.values():
            if task.status != "pending":
                continue

            # Check dependencies
            deps_met = all(
                self._tasks.get(dep) is not None and
                self._tasks.get(dep).status == "completed"
                for dep in task.dependencies
            )

            if deps_met:
                ready.append(task)

        # Sort by priority
        return sorted(ready, key=lambda t: t.priority, reverse=True)

    async def run_task(
        self,
        task: ScheduledTask,
        executor: Callable[[ScheduledTask], Any]
    ) -> None:
        """Run a single task with semaphore control."""
        async with self._semaphore:
            task.status = "running"
            task.started_at = datetime.utcnow()

            try:
                task.result = await asyncio.wait_for(
                    executor(task),
                    timeout=self.timeout_per_agent
                )
                task.status = "completed"
                self._completed_count += 1

            except asyncio.TimeoutError:
                task.status = "failed"
                task.error = "Timeout"
                self._failed_count += 1
                logger.warning(f"Task {task.agent_id} timed out")

            except Exception as e:
                task.status = "failed"
                task.error = str(e)
                self._failed_count += 1
                logger.error(f"Task {task.agent_id} failed: {e}")

            finally:
                task.completed_at = datetime.utcnow()

    async def run_all(
        self,
        executor: Callable[[ScheduledTask], Any]
    ) -> Dict[str, Any]:
        """
        Run all scheduled tasks according to execution mode.

        Args:
            executor: Async function to execute each task

        Returns:
            Summary of execution
        """
        self._running = True
        start_time = datetime.utcnow()

        try:
            if self.mode == ExecutionMode.SEQUENTIAL:
                await self._run_sequential(executor)
            elif self.mode == ExecutionMode.PARALLEL:
                await self._run_parallel(executor)
            else:  # ADAPTIVE
                await self._run_adaptive(executor)

        finally:
            self._running = False

        return {
            "duration_seconds": (datetime.utcnow() - start_time).total_seconds(),
            "total_tasks": len(self._tasks),
            "completed": self._completed_count,
            "failed": self._failed_count,
            "mode": self.mode.name,
        }

    async def _run_sequential(self, executor: Callable) -> None:
        """Run tasks sequentially by priority."""
        tasks_to_run = sorted(
            [t for t in self._tasks.values() if t.status == "pending"],
            key=lambda t: t.priority,
            reverse=True
        )

        for task in tasks_to_run:
            if not self._running:
                break
            await self.run_task(task, executor)

    async def _run_parallel(self, executor: Callable) -> None:
        """Run all tasks in parallel (with semaphore limit)."""
        tasks = [
            self.run_task(task, executor)
            for task in self._tasks.values()
            if task.status == "pending"
        ]
        await asyncio.gather(*tasks, return_exceptions=True)

    async def _run_adaptive(self, executor: Callable) -> None:
        """Run tasks adaptively based on findings."""
        while self._running:
            ready_tasks = self.get_ready_tasks()
            if not ready_tasks:
                break

            # In adaptive mode, start with batch execution
            # but can switch to sequential for chain analysis

            # Run ready tasks in parallel batches
            batch = ready_tasks[:self.max_concurrent]
            tasks = [self.run_task(task, executor) for task in batch]
            await asyncio.gather(*tasks, return_exceptions=True)

            # Check if we should add more tasks (chaining)
            # This would be triggered by the orchestrator based on findings

    def stop(self) -> None:
        """Stop scheduler execution."""
        self._running = False

    def get_task(self, agent_id: str) -> Optional[ScheduledTask]:
        """Get task by agent ID."""
        return self._tasks.get(agent_id)

    def get_completed_tasks(self) -> List[ScheduledTask]:
        """Get all completed tasks."""
        return [t for t in self._tasks.values() if t.status == "completed"]

    def get_failed_tasks(self) -> List[ScheduledTask]:
        """Get all failed tasks."""
        return [t for t in self._tasks.values() if t.status == "failed"]

    def get_stats(self) -> Dict[str, Any]:
        """Get scheduler statistics."""
        status_counts = {}
        for task in self._tasks.values():
            status_counts[task.status] = status_counts.get(task.status, 0) + 1

        return {
            "total_tasks": len(self._tasks),
            "status_counts": status_counts,
            "completed": self._completed_count,
            "failed": self._failed_count,
            "running": self._running,
            "mode": self.mode.name,
            "max_concurrent": self.max_concurrent,
        }

    def reset(self) -> None:
        """Reset scheduler state."""
        self._tasks.clear()
        self._completed_count = 0
        self._failed_count = 0
        self._running = False
