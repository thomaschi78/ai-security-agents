"""Tests for security testing agents."""

import pytest
import asyncio
from unittest.mock import MagicMock
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).parent.parent / "python"))

from agents.base import AgentState, PayloadStage
from agents.payload import (
    SQLiAgent, XSSAgent, CMDiAgent, LFIAgent,
    SSRFAgent, XXEAgent, Log4ShellAgent,
    create_agent, AGENT_CLASSES
)


class TestAgentState:
    """Tests for agent state management."""

    def test_payload_stage_order(self):
        """Test payload stages are in correct order."""
        stages = list(PayloadStage)
        assert stages[0] == PayloadStage.PROBE
        assert stages[1] == PayloadStage.CONFIRM
        assert stages[2] == PayloadStage.EXPLOIT
        assert stages[3] == PayloadStage.BYPASS

    def test_agent_state_values(self):
        """Test all agent states exist."""
        assert AgentState.IDLE
        assert AgentState.PERCEIVING
        assert AgentState.REASONING
        assert AgentState.ACTING
        assert AgentState.COMPLETED
        assert AgentState.ERROR


class TestSQLiAgent:
    """Tests for SQL injection agent."""

    def test_agent_properties(self):
        """Test agent has required properties."""
        agent = SQLiAgent()
        assert agent.vulnerability_type == "sqli"
        assert agent.cweid == 89
        assert agent.priority == 9

    def test_staged_payloads(self):
        """Test agent has payloads for all stages."""
        agent = SQLiAgent()
        payloads = agent.staged_payloads

        assert PayloadStage.PROBE in payloads
        assert PayloadStage.CONFIRM in payloads
        assert PayloadStage.EXPLOIT in payloads
        assert PayloadStage.BYPASS in payloads

        assert len(payloads[PayloadStage.PROBE]) > 0
        assert "'" in payloads[PayloadStage.PROBE]

    def test_detection_patterns(self):
        """Test detection patterns compile and match."""
        agent = SQLiAgent()
        patterns = agent.get_detection_patterns()

        assert len(patterns) > 0

        # Test known SQL error pattern
        test_response = "You have an error in your SQL syntax"
        matches = [p for p in patterns if p.search(test_response)]
        assert len(matches) > 0


class TestXSSAgent:
    """Tests for XSS agent."""

    def test_agent_properties(self):
        """Test agent has required properties."""
        agent = XSSAgent()
        assert agent.vulnerability_type == "xss"
        assert agent.cweid == 79

    def test_xss_payloads(self):
        """Test XSS payloads include script tags."""
        agent = XSSAgent()
        probe_payloads = agent.staged_payloads[PayloadStage.PROBE]

        script_payloads = [p for p in probe_payloads if "<script>" in p.lower()]
        assert len(script_payloads) > 0

    def test_detection_patterns(self):
        """Test XSS detection patterns."""
        agent = XSSAgent()
        patterns = agent.get_detection_patterns()

        # Should match script tag reflection
        test_response = "<script>alert(1)</script>"
        matches = [p for p in patterns if p.search(test_response)]
        assert len(matches) > 0


class TestCMDiAgent:
    """Tests for command injection agent."""

    def test_agent_properties(self):
        """Test agent has required properties."""
        agent = CMDiAgent()
        assert agent.vulnerability_type == "cmdi"
        assert agent.cweid == 78
        assert agent.priority == 10  # Critical priority

    def test_command_payloads(self):
        """Test command injection payloads."""
        agent = CMDiAgent()
        payloads = agent.staged_payloads[PayloadStage.PROBE]

        assert ";id" in payloads
        assert "|id" in payloads
        assert "$(id)" in payloads

    def test_etc_passwd_detection(self):
        """Test /etc/passwd content detection."""
        agent = CMDiAgent()
        patterns = agent.get_detection_patterns()

        test_response = "root:x:0:0:root:/root:/bin/bash"
        matches = [p for p in patterns if p.search(test_response)]
        assert len(matches) > 0


class TestSSRFAgent:
    """Tests for SSRF agent."""

    def test_agent_properties(self):
        """Test agent has required properties."""
        agent = SSRFAgent()
        assert agent.vulnerability_type == "ssrf"
        assert agent.cweid == 918

    def test_metadata_payloads(self):
        """Test cloud metadata endpoint payloads."""
        agent = SSRFAgent()
        payloads = agent.staged_payloads[PayloadStage.CONFIRM]

        # Should include AWS metadata
        aws_payloads = [p for p in payloads if "169.254.169.254" in p]
        assert len(aws_payloads) > 0


class TestLog4ShellAgent:
    """Tests for Log4Shell agent."""

    def test_agent_properties(self):
        """Test agent has required properties."""
        agent = Log4ShellAgent()
        assert agent.vulnerability_type == "log4shell"
        assert agent.cweid == 917
        assert agent.priority == 10  # Critical

    def test_jndi_payloads(self):
        """Test JNDI injection payloads."""
        agent = Log4ShellAgent()
        payloads = agent.staged_payloads[PayloadStage.PROBE]

        jndi_payloads = [p for p in payloads if "${jndi:" in p]
        assert len(jndi_payloads) > 0


class TestAgentFactory:
    """Tests for agent factory functions."""

    def test_create_agent(self):
        """Test agent creation from type string."""
        agent = create_agent("sqli")
        assert isinstance(agent, SQLiAgent)

        agent = create_agent("xss")
        assert isinstance(agent, XSSAgent)

    def test_create_unknown_agent(self):
        """Test creating unknown agent type raises error."""
        with pytest.raises(ValueError):
            create_agent("unknown_type")

    def test_all_agents_registered(self):
        """Test all expected agents are registered."""
        expected = [
            "sqli", "xss", "cmdi", "lfi", "ssrf",
            "xxe", "log4shell", "csrf", "ssti", "path_traversal"
        ]

        for agent_type in expected:
            assert agent_type in AGENT_CLASSES


class TestStageBasedMixin:
    """Tests for staged payload mixin."""

    def test_iterate_staged_payloads(self):
        """Test iterating through payloads by stage."""
        agent = SQLiAgent()

        stages_seen = set()
        payload_count = 0

        for stage, idx, payload in agent.iterate_staged_payloads():
            stages_seen.add(stage)
            payload_count += 1
            if payload_count > 50:
                break

        assert PayloadStage.PROBE in stages_seen

    def test_encode_payload(self):
        """Test payload encoding."""
        agent = SQLiAgent()

        payload = "' OR '1'='1"

        # URL encoding
        encoded = agent.encode_payload(payload, "url")
        assert "%27" in encoded  # Encoded quote

        # Double URL encoding
        double_encoded = agent.encode_payload(payload, "double_url")
        assert "%2527" in double_encoded


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
