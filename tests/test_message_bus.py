"""Tests for message bus communication."""

import pytest
import asyncio
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).parent.parent / "python"))

from communication import (
    MessageBus, Message, MessagePriority, MessageType,
    VulnerabilityMessage, ChainOpportunityMessage
)


class TestMessageBus:
    """Tests for async message bus."""

    @pytest.fixture
    def bus(self):
        """Create message bus for testing."""
        return MessageBus()

    @pytest.mark.asyncio
    async def test_publish_subscribe(self, bus):
        """Test basic pub/sub functionality."""
        received = []

        async def handler(msg):
            received.append(msg)

        bus.subscribe("test_subscriber", "test_topic", handler)
        await bus.start()

        try:
            await bus.publish("test_topic", {"data": "test"}, source="test")
            await asyncio.sleep(0.1)  # Allow message processing

            assert len(received) == 1
            assert received[0].payload["data"] == "test"
        finally:
            await bus.stop()

    @pytest.mark.asyncio
    async def test_topic_filtering(self, bus):
        """Test messages only go to matching topics."""
        received_a = []
        received_b = []

        async def handler_a(msg):
            received_a.append(msg)

        async def handler_b(msg):
            received_b.append(msg)

        bus.subscribe("sub_a", "topic_a", handler_a)
        bus.subscribe("sub_b", "topic_b", handler_b)
        await bus.start()

        try:
            await bus.publish("topic_a", {"for": "a"}, source="test")
            await asyncio.sleep(0.1)

            assert len(received_a) == 1
            assert len(received_b) == 0
        finally:
            await bus.stop()

    @pytest.mark.asyncio
    async def test_wildcard_subscription(self, bus):
        """Test wildcard topic matching."""
        received = []

        async def handler(msg):
            received.append(msg)

        bus.subscribe("wildcard_sub", "vulnerability_*", handler)
        await bus.start()

        try:
            await bus.publish("vulnerability_found", {"type": "sqli"}, source="test")
            await bus.publish("vulnerability_confirmed", {"type": "xss"}, source="test")
            await asyncio.sleep(0.1)

            assert len(received) == 2
        finally:
            await bus.stop()

    @pytest.mark.asyncio
    async def test_unsubscribe(self, bus):
        """Test unsubscribing from topics."""
        received = []

        async def handler(msg):
            received.append(msg)

        bus.subscribe("unsub_test", "test_topic", handler)
        await bus.start()

        try:
            await bus.publish("test_topic", {"n": 1}, source="test")
            await asyncio.sleep(0.1)
            assert len(received) == 1

            bus.unsubscribe("unsub_test", "test_topic")

            await bus.publish("test_topic", {"n": 2}, source="test")
            await asyncio.sleep(0.1)
            assert len(received) == 1  # Still 1, didn't receive second
        finally:
            await bus.stop()

    @pytest.mark.asyncio
    async def test_message_priority(self, bus):
        """Test message priority ordering."""
        received = []

        async def handler(msg):
            received.append(msg.priority)
            await asyncio.sleep(0.01)

        bus.subscribe("priority_test", "test", handler)
        await bus.start()

        try:
            # Publish in reverse priority order
            await bus.publish("test", {}, source="test", priority=MessagePriority.LOW)
            await bus.publish("test", {}, source="test", priority=MessagePriority.CRITICAL)
            await bus.publish("test", {}, source="test", priority=MessagePriority.NORMAL)

            await asyncio.sleep(0.2)

            # Critical should be processed first
            assert received[0] == MessagePriority.CRITICAL
        finally:
            await bus.stop()


class TestMessageTypes:
    """Tests for message type definitions."""

    def test_message_to_dict(self):
        """Test message serialization."""
        msg = Message(
            topic="test",
            source="agent_1",
            payload={"key": "value"},
            priority=MessagePriority.HIGH
        )

        data = msg.to_dict()

        assert data["topic"] == "test"
        assert data["source"] == "agent_1"
        assert data["payload"]["key"] == "value"
        assert data["priority"] == "HIGH"

    def test_message_from_dict(self):
        """Test message deserialization."""
        data = {
            "id": "test-id",
            "type": "SCAN_PROGRESS",
            "topic": "test",
            "source": "agent_1",
            "priority": "HIGH",
            "payload": {"data": 123}
        }

        msg = Message.from_dict(data)

        assert msg.id == "test-id"
        assert msg.type == MessageType.SCAN_PROGRESS
        assert msg.priority == MessagePriority.HIGH

    def test_vulnerability_message(self):
        """Test vulnerability message type."""
        msg = VulnerabilityMessage(
            vulnerability_type="sqli",
            cweid=89,
            confidence=0.85,
            url="http://example.com",
            parameter="id"
        )

        assert msg.type == MessageType.VULNERABILITY_FOUND
        assert msg.topic == "vulnerability_found"
        assert msg.priority == MessagePriority.HIGH

    def test_chain_opportunity_message(self):
        """Test chain opportunity message type."""
        msg = ChainOpportunityMessage(
            source_vuln="sqli",
            target_vuln="ssrf"
        )

        assert msg.type == MessageType.CHAIN_OPPORTUNITY
        assert msg.topic == "chain_opportunity"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
