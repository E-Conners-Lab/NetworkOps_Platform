"""
Tests for Execution Loop, Rate Limiter, and Event Bus.

Validates:
- Event-driven dispatch
- Rate limiter blocks excess actions
- Circuit breaker triggers after consecutive failures
- Timeout isolation
- Event bus pub/sub
"""
import os
import sys
import asyncio
import time

_project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

import pytest
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

from agents.config import reset_config
from agents.db.models import (
    AgentDecision,
    AgentDatabase,
    DecisionStatus,
    ProposedAction,
    SymptomCategory,
)
from agents.events import AgentEventBus, reset_event_bus
from agents.execution.rate_limiter import ActionRateLimiter, RateLimiterConfig


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def temp_db(consolidated_db):
    """Create an AgentDatabase backed by the consolidated test DB."""
    import agents.db.models as models
    models._db = AgentDatabase()
    yield models._db


@pytest.fixture
def sample_decision():
    """Create a sample approved decision."""
    action = ProposedAction(
        action_type="investigate",
        tool_name="health_check",
        parameters={"device": "R1"},
        expected_outcome="Diagnosed",
    )
    decision = AgentDecision.create(
        device="R1",
        symptom="interface_down",
        symptom_category=SymptomCategory.INTERFACE,
        triggering_event_id="evt-001",
        reasoning_steps=[],
        knowledge_base_version="1.0.0",
        proposed_action=action,
        risk_score=25,
        confidence=0.8,
        trace_id="trace-001",
    )
    decision.status = DecisionStatus.APPROVED
    return decision


@pytest.fixture
def config_decision():
    """Create a sample config-change decision."""
    action = ProposedAction(
        action_type="send_config",
        tool_name="send_config",
        parameters={"device": "R2", "commands": ["ip route 0.0.0.0 0.0.0.0 10.0.0.1"]},
        expected_outcome="Route added",
    )
    decision = AgentDecision.create(
        device="R2",
        symptom="routing_issue",
        symptom_category=SymptomCategory.ROUTING,
        triggering_event_id="evt-002",
        reasoning_steps=[],
        knowledge_base_version="1.0.0",
        proposed_action=action,
        risk_score=60,
        confidence=0.7,
        trace_id="trace-002",
    )
    decision.status = DecisionStatus.APPROVED
    return decision


# ===========================================================================
# Event Bus Tests
# ===========================================================================

class TestEventBus:
    """Tests for AgentEventBus."""

    @pytest.fixture(autouse=True)
    def reset_bus(self):
        reset_event_bus()
        yield
        reset_event_bus()

    @pytest.mark.asyncio
    async def test_publish_subscribe(self):
        """Test basic pub/sub works."""
        bus = AgentEventBus()
        received = []

        async def handler(data):
            received.append(data)

        bus.subscribe("test_event", handler)
        await bus.publish("test_event", {"key": "value"})

        assert len(received) == 1
        assert received[0]["key"] == "value"

    @pytest.mark.asyncio
    async def test_multiple_subscribers(self):
        """Test multiple subscribers receive the event."""
        bus = AgentEventBus()
        received_a = []
        received_b = []

        async def handler_a(data):
            received_a.append(data)

        async def handler_b(data):
            received_b.append(data)

        bus.subscribe("test", handler_a)
        bus.subscribe("test", handler_b)
        await bus.publish("test", {"x": 1})

        assert len(received_a) == 1
        assert len(received_b) == 1

    @pytest.mark.asyncio
    async def test_no_subscribers(self):
        """Publishing to no subscribers does not raise."""
        bus = AgentEventBus()
        await bus.publish("nobody_listening", {"data": True})

    @pytest.mark.asyncio
    async def test_subscriber_exception_does_not_break_others(self):
        """A failing subscriber should not prevent others from receiving."""
        bus = AgentEventBus()
        received = []

        async def bad_handler(data):
            raise RuntimeError("boom")

        async def good_handler(data):
            received.append(data)

        bus.subscribe("test", bad_handler)
        bus.subscribe("test", good_handler)
        await bus.publish("test", {"ok": True})

        assert len(received) == 1

    @pytest.mark.asyncio
    async def test_unsubscribe(self):
        """Test unsubscribe removes the handler."""
        bus = AgentEventBus()
        received = []

        async def handler(data):
            received.append(data)

        bus.subscribe("test", handler)
        bus.unsubscribe("test", handler)
        await bus.publish("test", {"should_not_arrive": True})

        assert len(received) == 0

    def test_subscriber_counts(self):
        """Test subscriber count reporting."""
        bus = AgentEventBus()

        async def h1(data): pass
        async def h2(data): pass

        bus.subscribe("a", h1)
        bus.subscribe("a", h2)
        bus.subscribe("b", h1)

        counts = bus.subscriber_counts
        assert counts["a"] == 2
        assert counts["b"] == 1


# ===========================================================================
# Rate Limiter Tests
# ===========================================================================

class TestRateLimiter:
    """Tests for ActionRateLimiter."""

    def test_allows_within_limit(self, sample_decision):
        """Actions within the limit are allowed."""
        limiter = ActionRateLimiter(RateLimiterConfig(max_actions_per_hour=5))
        allowed, reason = limiter.can_execute(sample_decision)
        assert allowed is True
        assert reason == ""

    def test_blocks_global_limit(self, sample_decision):
        """Actions exceeding global limit are blocked."""
        limiter = ActionRateLimiter(RateLimiterConfig(max_actions_per_hour=3))

        for _ in range(3):
            limiter.record_execution(sample_decision)

        allowed, reason = limiter.can_execute(sample_decision)
        assert allowed is False
        assert "global_hourly_limit" in reason

    def test_blocks_per_device_limit(self, sample_decision):
        """Actions exceeding per-device limit are blocked."""
        limiter = ActionRateLimiter(RateLimiterConfig(
            max_actions_per_hour=100,
            max_per_device_per_hour=2,
        ))

        for _ in range(2):
            limiter.record_execution(sample_decision)

        allowed, reason = limiter.can_execute(sample_decision)
        assert allowed is False
        assert "per_device_limit" in reason

    def test_blocks_config_change_limit(self, config_decision):
        """Config changes exceeding the limit are blocked."""
        limiter = ActionRateLimiter(RateLimiterConfig(
            max_actions_per_hour=100,
            max_config_changes_per_hour=2,
            max_per_device_per_hour=100,
        ))

        for _ in range(2):
            limiter.record_execution(config_decision)

        allowed, reason = limiter.can_execute(config_decision)
        assert allowed is False
        assert "config_change_limit" in reason

    def test_circuit_breaker_triggers(self, sample_decision):
        """Circuit breaker opens after consecutive failures."""
        limiter = ActionRateLimiter(RateLimiterConfig(
            circuit_breaker_threshold=3,
            cooldown_after_failure=60,
        ))

        for _ in range(3):
            limiter.record_failure()

        allowed, reason = limiter.can_execute(sample_decision)
        assert allowed is False
        assert "circuit_breaker_open" in reason

    def test_circuit_breaker_resets_on_success(self, sample_decision):
        """Circuit breaker resets after a successful execution."""
        limiter = ActionRateLimiter(RateLimiterConfig(
            circuit_breaker_threshold=3,
            cooldown_after_failure=0,  # disable cooldown for this test
        ))

        limiter.record_failure()
        limiter.record_failure()
        limiter.record_success()
        limiter.record_failure()

        # Should still be allowed (counter reset by success, only 1 consecutive failure)
        allowed, _ = limiter.can_execute(sample_decision)
        assert allowed is True

    def test_cooldown_after_failure(self, sample_decision):
        """Cooldown period after a failure blocks execution."""
        limiter = ActionRateLimiter(RateLimiterConfig(
            cooldown_after_failure=60,
            circuit_breaker_threshold=100,  # won't trigger
        ))

        limiter.record_failure()

        allowed, reason = limiter.can_execute(sample_decision)
        assert allowed is False
        assert "cooldown_after_failure" in reason

    def test_status_reporting(self, sample_decision):
        """Status report returns correct values."""
        limiter = ActionRateLimiter(RateLimiterConfig(max_actions_per_hour=10))
        limiter.record_execution(sample_decision)
        limiter.record_execution(sample_decision)

        status = limiter.get_status()
        assert status["actions_this_hour"] == 2
        assert status["consecutive_failures"] == 0
        assert status["circuit_breaker_open"] is False

    def test_reset(self, sample_decision):
        """Reset clears all state."""
        limiter = ActionRateLimiter(RateLimiterConfig(max_actions_per_hour=1))
        limiter.record_execution(sample_decision)

        allowed, _ = limiter.can_execute(sample_decision)
        assert allowed is False

        limiter.reset()

        allowed, _ = limiter.can_execute(sample_decision)
        assert allowed is True


# ===========================================================================
# Execution Loop Tests (unit, mocked executor)
# ===========================================================================

class TestExecutionLoop:
    """Tests for ExecutionLoop dispatch logic."""

    @pytest.fixture(autouse=True)
    def setup(self, temp_db):
        reset_event_bus()
        reset_config()
        yield

    @pytest.mark.asyncio
    async def test_dispatch_approved_decision(self, sample_decision, temp_db):
        """An approved decision dispatches to the executor."""
        temp_db.save_decision(sample_decision)

        from agents.execution.execution_loop import ExecutionLoop

        loop = ExecutionLoop()

        # Mock the executor and config
        loop._executor = MagicMock()
        loop._executor.execute = AsyncMock(return_value={"status": "success"})
        loop._config = MagicMock()
        loop._config.autonomous_execution = True
        loop._rate_limiter = ActionRateLimiter(RateLimiterConfig(max_actions_per_hour=10))

        await loop._dispatch(sample_decision)

        # Wait for the task to complete
        if loop._active_tasks:
            await asyncio.wait(loop._active_tasks, timeout=5)

        loop._executor.execute.assert_called_once()

    @pytest.mark.asyncio
    async def test_dispatch_blocked_by_autonomous_flag(self, sample_decision, temp_db):
        """Dispatch does nothing when autonomous execution is disabled."""
        from agents.execution.execution_loop import ExecutionLoop

        loop = ExecutionLoop()
        loop._executor = MagicMock()
        loop._executor.execute = AsyncMock()
        loop._config = MagicMock()
        loop._config.autonomous_execution = False

        await loop._dispatch(sample_decision)

        loop._executor.execute.assert_not_called()

    @pytest.mark.asyncio
    async def test_dispatch_blocked_by_rate_limiter(self, sample_decision, temp_db):
        """Dispatch is blocked when rate limiter says no."""
        from agents.execution.execution_loop import ExecutionLoop

        loop = ExecutionLoop()
        loop._executor = MagicMock()
        loop._executor.execute = AsyncMock()
        loop._config = MagicMock()
        loop._config.autonomous_execution = True

        # Saturate the limiter
        loop._rate_limiter = ActionRateLimiter(RateLimiterConfig(max_actions_per_hour=0))

        await loop._dispatch(sample_decision)

        loop._executor.execute.assert_not_called()

    @pytest.mark.asyncio
    async def test_event_bus_triggers_dispatch(self, sample_decision, temp_db):
        """Publishing decision_approved on the bus triggers dispatch."""
        temp_db.save_decision(sample_decision)

        from agents.execution.execution_loop import ExecutionLoop

        loop = ExecutionLoop()
        loop._executor = MagicMock()
        loop._executor.execute = AsyncMock(return_value={"status": "success"})
        loop._config = MagicMock()
        loop._config.autonomous_execution = True
        loop._rate_limiter = ActionRateLimiter(RateLimiterConfig(max_actions_per_hour=10))

        # Subscribe manually (simulating start without the poll task)
        from agents.events import get_event_bus
        bus = get_event_bus()
        bus.subscribe("decision_approved", loop._on_decision_approved)

        await bus.publish("decision_approved", {"decision_id": sample_decision.id})

        # Wait for execution task
        await asyncio.sleep(0.1)
        if loop._active_tasks:
            await asyncio.wait(loop._active_tasks, timeout=5)

        loop._executor.execute.assert_called_once()

    @pytest.mark.asyncio
    async def test_timeout_marks_decision_failed(self, sample_decision, temp_db):
        """A timed-out execution marks the decision as FAILED."""
        temp_db.save_decision(sample_decision)

        from agents.execution import execution_loop as el_module

        # Patch timeout to something small
        original_timeout = el_module.EXECUTION_TIMEOUT
        el_module.EXECUTION_TIMEOUT = 0.01  # 10ms

        try:
            from agents.execution.execution_loop import ExecutionLoop

            loop = ExecutionLoop()

            async def slow_execute(decision):
                await asyncio.sleep(10)
                return {"status": "success"}

            loop._executor = MagicMock()
            loop._executor.execute = slow_execute
            loop._config = MagicMock()
            loop._config.autonomous_execution = True
            loop._rate_limiter = ActionRateLimiter(RateLimiterConfig(max_actions_per_hour=10))

            await loop._dispatch(sample_decision)

            if loop._active_tasks:
                await asyncio.wait(loop._active_tasks, timeout=5)

            # Decision should be marked failed
            updated = temp_db.get_decision(sample_decision.id)
            assert updated.status == DecisionStatus.FAILED

        finally:
            el_module.EXECUTION_TIMEOUT = original_timeout
