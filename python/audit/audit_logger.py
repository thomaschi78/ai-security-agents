"""Structured audit logging for security testing."""

import asyncio
import json
import logging
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional
import uuid
from enum import Enum


class LogType(Enum):
    """Types of audit log entries."""
    PERCEPTION = "perception"
    REASONING = "reasoning"
    ACTION = "action"
    FINDING = "finding"
    ERROR = "error"
    SESSION = "session"
    AGENT = "agent"


class AuditLogger:
    """
    Structured audit logger for security testing.

    Features:
    - JSONL format for machine parsing
    - Console output for human readability
    - Session tracking with correlation IDs
    - Async-safe logging
    """

    def __init__(
        self,
        log_dir: Optional[str] = None,
        session_id: Optional[str] = None,
        console_output: bool = True,
        log_level: int = logging.INFO,
        max_payload_length: int = 500
    ):
        """
        Initialize audit logger.

        Args:
            log_dir: Directory for log files (None = no file logging)
            session_id: Session ID (auto-generated if not provided)
            console_output: Enable console output
            log_level: Logging level
            max_payload_length: Max length for payload truncation
        """
        self.session_id = session_id or str(uuid.uuid4())
        self.console_output = console_output
        self.max_payload_length = max_payload_length

        self._log_dir = Path(log_dir) if log_dir else None
        self._log_file = None
        self._lock = asyncio.Lock()
        self._entries: List[Dict[str, Any]] = []
        self._stats = {
            "perceptions": 0,
            "reasonings": 0,
            "actions": 0,
            "findings": 0,
            "errors": 0,
        }

        # Setup console logger
        self._console_logger = logging.getLogger(f"audit.{self.session_id[:8]}")
        self._console_logger.setLevel(log_level)

        if console_output and not self._console_logger.handlers:
            handler = logging.StreamHandler(sys.stdout)
            handler.setFormatter(AuditFormatter())
            self._console_logger.addHandler(handler)
            self._console_logger.propagate = False

        # Create log file
        if self._log_dir:
            self._log_dir.mkdir(parents=True, exist_ok=True)
            timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            self._log_file = self._log_dir / f"audit_{timestamp}_{self.session_id[:8]}.jsonl"

    async def start_session(self, metadata: Optional[Dict[str, Any]] = None) -> None:
        """Log session start."""
        await self._log_entry(LogType.SESSION, {
            "event": "session_start",
            "session_id": self.session_id,
            "timestamp": datetime.utcnow().isoformat(),
            "metadata": metadata or {},
        })

    async def end_session(self, summary: Optional[Dict[str, Any]] = None) -> None:
        """Log session end with summary."""
        await self._log_entry(LogType.SESSION, {
            "event": "session_end",
            "session_id": self.session_id,
            "timestamp": datetime.utcnow().isoformat(),
            "stats": self._stats,
            "summary": summary or {},
        })

    async def log_perception(self, data: Dict[str, Any]) -> None:
        """Log perception phase data."""
        self._stats["perceptions"] += 1

        entry = {
            "type": LogType.PERCEPTION.value,
            "timestamp": datetime.utcnow().isoformat(),
            "session_id": data.get("session_id", self.session_id),
            "agent_id": data.get("agent_id", "unknown"),
            "payload": self._truncate(data.get("payload", "")),
            "status_code": data.get("status_code", 0),
            "response_time_ms": data.get("response_time_ms", 0),
            "indicators": data.get("indicators", []),
            "reflections": data.get("reflections", []),
        }

        await self._log_entry(LogType.PERCEPTION, entry)

    async def log_reasoning(self, data: Dict[str, Any]) -> None:
        """Log reasoning phase result."""
        self._stats["reasonings"] += 1

        entry = {
            "type": LogType.REASONING.value,
            "timestamp": datetime.utcnow().isoformat(),
            "session_id": data.get("session_id", self.session_id),
            "agent_id": data.get("agent_id", "unknown"),
            "decision": data.get("decision", ""),
            "confidence": data.get("confidence", 0.0),
            "reasoning_chain": data.get("reasoning_chain", []),
        }

        await self._log_entry(LogType.REASONING, entry)

    async def log_action(self, data: Dict[str, Any]) -> None:
        """Log action phase execution."""
        self._stats["actions"] += 1

        entry = {
            "type": LogType.ACTION.value,
            "timestamp": datetime.utcnow().isoformat(),
            "session_id": data.get("session_id", self.session_id),
            "agent_id": data.get("agent_id", "unknown"),
            "action_type": data.get("action_type", data.get("type", "")),
            "success": data.get("success", False),
            "details": {k: v for k, v in data.items()
                       if k not in ["session_id", "agent_id", "action_type", "type", "success"]},
        }

        await self._log_entry(LogType.ACTION, entry)

    async def log_finding(self, finding: Dict[str, Any]) -> None:
        """Log vulnerability finding."""
        self._stats["findings"] += 1

        entry = {
            "type": LogType.FINDING.value,
            "timestamp": datetime.utcnow().isoformat(),
            "session_id": finding.get("session_id", self.session_id),
            "finding_id": finding.get("id", str(uuid.uuid4())),
            "agent_id": finding.get("agent_id", "unknown"),
            "vulnerability_type": finding.get("vulnerability_type", ""),
            "cweid": finding.get("cweid", 0),
            "url": finding.get("url", ""),
            "parameter": finding.get("parameter", ""),
            "confidence": finding.get("confidence", 0.0),
            "indicators": finding.get("indicators", []),
            "evidence": self._truncate(str(finding.get("evidence", ""))),
        }

        await self._log_entry(LogType.FINDING, entry)

    async def log_error(self, data: Dict[str, Any]) -> None:
        """Log error."""
        self._stats["errors"] += 1

        entry = {
            "type": LogType.ERROR.value,
            "timestamp": datetime.utcnow().isoformat(),
            "session_id": data.get("session_id", self.session_id),
            "agent_id": data.get("agent_id", "unknown"),
            "error": data.get("error", ""),
            "context": data.get("context", {}),
        }

        await self._log_entry(LogType.ERROR, entry)

    async def log_agent_event(self, event: str, agent_id: str, data: Optional[Dict] = None) -> None:
        """Log agent lifecycle event."""
        entry = {
            "type": LogType.AGENT.value,
            "timestamp": datetime.utcnow().isoformat(),
            "session_id": self.session_id,
            "agent_id": agent_id,
            "event": event,
            "data": data or {},
        }

        await self._log_entry(LogType.AGENT, entry)

    async def _log_entry(self, log_type: LogType, entry: Dict[str, Any]) -> None:
        """Write log entry to file and console."""
        async with self._lock:
            self._entries.append(entry)

            # Write to file
            if self._log_file:
                with open(self._log_file, "a") as f:
                    f.write(json.dumps(entry) + "\n")

            # Write to console
            if self.console_output:
                self._log_to_console(log_type, entry)

    def _log_to_console(self, log_type: LogType, entry: Dict[str, Any]) -> None:
        """Format and log entry to console."""
        if log_type == LogType.PERCEPTION:
            self._console_logger.info(
                f"[{entry.get('agent_id', '?')[:12]}] PERCEIVE "
                f"payload={entry.get('payload', '')[:50]} "
                f"status={entry.get('status_code', 0)} "
                f"indicators={len(entry.get('indicators', []))}"
            )
        elif log_type == LogType.REASONING:
            self._console_logger.info(
                f"[{entry.get('agent_id', '?')[:12]}] REASON "
                f"decision={entry.get('decision', '?')} "
                f"confidence={entry.get('confidence', 0):.2f}"
            )
        elif log_type == LogType.ACTION:
            self._console_logger.info(
                f"[{entry.get('agent_id', '?')[:12]}] ACT "
                f"type={entry.get('action_type', '?')} "
                f"success={entry.get('success', False)}"
            )
        elif log_type == LogType.FINDING:
            self._console_logger.warning(
                f"[{entry.get('agent_id', '?')[:12]}] FINDING "
                f"type={entry.get('vulnerability_type', '?')} "
                f"confidence={entry.get('confidence', 0):.2f} "
                f"url={entry.get('url', '?')}"
            )
        elif log_type == LogType.ERROR:
            self._console_logger.error(
                f"[{entry.get('agent_id', '?')[:12]}] ERROR "
                f"{entry.get('error', 'Unknown error')}"
            )
        elif log_type == LogType.AGENT:
            self._console_logger.debug(
                f"[{entry.get('agent_id', '?')[:12]}] {entry.get('event', '?')}"
            )
        elif log_type == LogType.SESSION:
            event = entry.get("event", "")
            if event == "session_start":
                self._console_logger.info(f"=== Session Started: {entry.get('session_id', '?')[:8]} ===")
            elif event == "session_end":
                self._console_logger.info(
                    f"=== Session Ended: findings={self._stats['findings']} "
                    f"errors={self._stats['errors']} ==="
                )

    def _truncate(self, text: str) -> str:
        """Truncate text to max length."""
        if len(text) > self.max_payload_length:
            return text[:self.max_payload_length] + "..."
        return text

    def get_entries(self, log_type: Optional[LogType] = None) -> List[Dict[str, Any]]:
        """Get log entries, optionally filtered by type."""
        if log_type:
            return [e for e in self._entries if e.get("type") == log_type.value]
        return self._entries.copy()

    def get_stats(self) -> Dict[str, Any]:
        """Get logging statistics."""
        return {
            **self._stats,
            "total_entries": len(self._entries),
            "session_id": self.session_id,
            "log_file": str(self._log_file) if self._log_file else None,
        }


class AuditFormatter(logging.Formatter):
    """Custom formatter for audit log console output."""

    COLORS = {
        logging.DEBUG: "\033[36m",    # Cyan
        logging.INFO: "\033[32m",     # Green
        logging.WARNING: "\033[33m",  # Yellow
        logging.ERROR: "\033[31m",    # Red
    }
    RESET = "\033[0m"

    def format(self, record: logging.LogRecord) -> str:
        color = self.COLORS.get(record.levelno, "")
        timestamp = datetime.utcnow().strftime("%H:%M:%S")
        return f"{color}[{timestamp}] {record.getMessage()}{self.RESET}"
