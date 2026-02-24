"""Async pub/sub message bus for inter-agent communication."""

import asyncio
import re
from typing import Any, Callable, Dict, List, Optional, Set
from dataclasses import dataclass, field
from datetime import datetime
import logging
from collections import defaultdict

from .message_types import Message, MessagePriority, get_topic_pattern


logger = logging.getLogger(__name__)


@dataclass
class Subscription:
    """Represents a topic subscription."""
    subscriber_id: str
    topic_pattern: str
    callback: Callable[[Message], Any]
    is_async: bool = True
    filter_func: Optional[Callable[[Message], bool]] = None
    created_at: datetime = field(default_factory=datetime.utcnow)

    def matches_topic(self, topic: str) -> bool:
        """Check if a topic matches this subscription's pattern."""
        pattern = get_topic_pattern(self.topic_pattern)
        return bool(re.match(pattern, topic))


class MessageBus:
    """
    Async pub/sub message bus for agent communication.

    Features:
    - Topic-based routing with wildcard support
    - Priority queue for message ordering
    - Async message delivery
    - Subscription filtering
    """

    def __init__(self, max_queue_size: int = 10000):
        self._subscriptions: Dict[str, List[Subscription]] = defaultdict(list)
        self._message_queue: asyncio.PriorityQueue = asyncio.PriorityQueue(maxsize=max_queue_size)
        self._running = False
        self._processor_task: Optional[asyncio.Task] = None
        self._message_history: List[Message] = []
        self._max_history = 1000
        self._stats = {
            "messages_published": 0,
            "messages_delivered": 0,
            "delivery_errors": 0,
        }

    async def start(self) -> None:
        """Start the message bus processor."""
        if self._running:
            return

        self._running = True
        self._processor_task = asyncio.create_task(self._process_messages())
        logger.info("Message bus started")

    async def stop(self) -> None:
        """Stop the message bus processor."""
        self._running = False
        if self._processor_task:
            self._processor_task.cancel()
            try:
                await self._processor_task
            except asyncio.CancelledError:
                pass
        logger.info("Message bus stopped")

    def subscribe(
        self,
        subscriber_id: str,
        topic_pattern: str,
        callback: Callable[[Message], Any],
        is_async: bool = True,
        filter_func: Optional[Callable[[Message], bool]] = None
    ) -> str:
        """
        Subscribe to a topic pattern.

        Args:
            subscriber_id: Unique identifier for the subscriber
            topic_pattern: Topic pattern (supports * wildcard)
            callback: Function to call when message received
            is_async: Whether callback is async
            filter_func: Optional filter function

        Returns:
            Subscription ID
        """
        sub = Subscription(
            subscriber_id=subscriber_id,
            topic_pattern=topic_pattern,
            callback=callback,
            is_async=is_async,
            filter_func=filter_func
        )

        self._subscriptions[topic_pattern].append(sub)
        logger.debug(f"Subscription created: {subscriber_id} -> {topic_pattern}")

        return f"{subscriber_id}:{topic_pattern}"

    def unsubscribe(self, subscriber_id: str, topic_pattern: Optional[str] = None) -> int:
        """
        Unsubscribe from topics.

        Args:
            subscriber_id: Subscriber to remove
            topic_pattern: Specific pattern to unsubscribe from, or None for all

        Returns:
            Number of subscriptions removed
        """
        removed = 0

        patterns_to_check = [topic_pattern] if topic_pattern else list(self._subscriptions.keys())

        for pattern in patterns_to_check:
            if pattern in self._subscriptions:
                original_count = len(self._subscriptions[pattern])
                self._subscriptions[pattern] = [
                    s for s in self._subscriptions[pattern]
                    if s.subscriber_id != subscriber_id
                ]
                removed += original_count - len(self._subscriptions[pattern])

                if not self._subscriptions[pattern]:
                    del self._subscriptions[pattern]

        logger.debug(f"Removed {removed} subscriptions for {subscriber_id}")
        return removed

    async def publish(
        self,
        topic: str,
        payload: Dict[str, Any],
        source: str = "unknown",
        priority: MessagePriority = MessagePriority.NORMAL,
        correlation_id: Optional[str] = None,
        target_agent: Optional[str] = None
    ) -> str:
        """
        Publish a message to a topic.

        Args:
            topic: Target topic
            payload: Message payload
            source: Source identifier
            priority: Message priority
            correlation_id: Optional correlation ID for tracking
            target_agent: Optional specific target agent

        Returns:
            Message ID
        """
        message = Message(
            topic=topic,
            source=source,
            payload=payload,
            priority=priority,
            correlation_id=correlation_id,
            target_agent=target_agent
        )

        # Priority queue uses (priority_value, timestamp, message) for ordering
        # Lower priority value = higher priority (so we negate)
        queue_priority = -priority.value

        await self._message_queue.put((
            queue_priority,
            message.timestamp.timestamp(),
            message
        ))

        self._stats["messages_published"] += 1
        logger.debug(f"Published message {message.id} to {topic}")

        return message.id

    async def publish_message(self, message: Message) -> str:
        """Publish a pre-constructed message."""
        queue_priority = -message.priority.value

        await self._message_queue.put((
            queue_priority,
            message.timestamp.timestamp(),
            message
        ))

        self._stats["messages_published"] += 1
        return message.id

    async def _process_messages(self) -> None:
        """Process messages from the queue."""
        while self._running:
            try:
                # Get next message with timeout
                try:
                    _, _, message = await asyncio.wait_for(
                        self._message_queue.get(),
                        timeout=1.0
                    )
                except asyncio.TimeoutError:
                    continue

                # Deliver to matching subscribers
                await self._deliver_message(message)

                # Store in history
                self._message_history.append(message)
                if len(self._message_history) > self._max_history:
                    self._message_history.pop(0)

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error processing message: {e}")

    async def _deliver_message(self, message: Message) -> None:
        """Deliver message to all matching subscribers."""
        delivered_to: Set[str] = set()

        for pattern, subscriptions in self._subscriptions.items():
            for sub in subscriptions:
                # Check if topic matches
                if not sub.matches_topic(message.topic):
                    continue

                # Check if targeting specific agent
                if message.target_agent and message.target_agent != sub.subscriber_id:
                    continue

                # Check filter function
                if sub.filter_func and not sub.filter_func(message):
                    continue

                # Avoid duplicate delivery
                if sub.subscriber_id in delivered_to:
                    continue

                try:
                    if sub.is_async:
                        await sub.callback(message)
                    else:
                        sub.callback(message)

                    delivered_to.add(sub.subscriber_id)
                    self._stats["messages_delivered"] += 1

                except Exception as e:
                    logger.error(f"Error delivering to {sub.subscriber_id}: {e}")
                    self._stats["delivery_errors"] += 1

    async def request_response(
        self,
        topic: str,
        payload: Dict[str, Any],
        source: str,
        timeout: float = 30.0
    ) -> Optional[Message]:
        """
        Send a request and wait for a response.

        Args:
            topic: Request topic
            payload: Request payload
            source: Source identifier
            timeout: Timeout in seconds

        Returns:
            Response message or None if timeout
        """
        response_future: asyncio.Future = asyncio.get_event_loop().create_future()
        correlation_id = await self.publish(topic, payload, source)

        response_topic = f"{topic}_response"

        def handle_response(msg: Message):
            if msg.correlation_id == correlation_id:
                response_future.set_result(msg)

        sub_id = self.subscribe(
            f"{source}_response",
            response_topic,
            handle_response,
            is_async=False
        )

        try:
            return await asyncio.wait_for(response_future, timeout)
        except asyncio.TimeoutError:
            logger.warning(f"Request timeout for {topic}")
            return None
        finally:
            self.unsubscribe(f"{source}_response", response_topic)

    def get_stats(self) -> Dict[str, Any]:
        """Get message bus statistics."""
        return {
            **self._stats,
            "queue_size": self._message_queue.qsize(),
            "subscriptions": sum(len(subs) for subs in self._subscriptions.values()),
            "topics": list(self._subscriptions.keys()),
        }

    def get_history(
        self,
        topic: Optional[str] = None,
        source: Optional[str] = None,
        limit: int = 100
    ) -> List[Message]:
        """Get message history with optional filtering."""
        messages = self._message_history

        if topic:
            messages = [m for m in messages if m.topic == topic]
        if source:
            messages = [m for m in messages if m.source == source]

        return messages[-limit:]


class MessageBusContext:
    """Context manager for message bus operations."""

    def __init__(self, bus: MessageBus):
        self.bus = bus
        self._subscriptions: List[str] = []

    async def __aenter__(self) -> "MessageBusContext":
        await self.bus.start()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        for sub in self._subscriptions:
            parts = sub.split(":", 1)
            if len(parts) == 2:
                self.bus.unsubscribe(parts[0], parts[1])
        await self.bus.stop()

    def subscribe(self, *args, **kwargs) -> str:
        sub_id = self.bus.subscribe(*args, **kwargs)
        self._subscriptions.append(sub_id)
        return sub_id
