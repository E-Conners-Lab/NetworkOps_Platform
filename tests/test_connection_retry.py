"""Tests for connection retry/backoff logic in core.connection_pool."""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from core.connection_pool import ConnectionPool


@pytest.fixture
def pool():
    """A connection pool with fast retry settings for testing."""
    return ConnectionPool(
        max_per_device=3,
        max_idle_seconds=300,
        max_age_seconds=600,
        max_retries=3,
        base_delay=0.01,  # Fast for tests
    )


# ---------------------------------------------------------------------------
# Retry behavior
# ---------------------------------------------------------------------------

class TestRetryBehavior:
    @pytest.mark.asyncio
    async def test_succeeds_on_first_try(self, pool):
        call_count = 0

        async def factory():
            nonlocal call_count
            call_count += 1
            return "connected"

        breaker = MagicMock()
        breaker.allow_request.return_value = True
        pool._breakers["R1"] = breaker

        result = await pool._with_retries(factory, "R1")
        assert result == "connected"
        assert call_count == 1
        breaker.record_success.assert_called_once()

    @pytest.mark.asyncio
    async def test_retries_on_failure_then_succeeds(self, pool):
        attempt = 0

        async def factory():
            nonlocal attempt
            attempt += 1
            if attempt < 3:
                raise ConnectionError(f"fail #{attempt}")
            return "ok"

        breaker = MagicMock()
        breaker.allow_request.return_value = True
        pool._breakers["R2"] = breaker

        result = await pool._with_retries(factory, "R2")
        assert result == "ok"
        assert attempt == 3
        assert pool._stats["connections_retried"] == 2

    @pytest.mark.asyncio
    async def test_all_retries_exhausted(self, pool):
        async def factory():
            raise ConnectionError("always fails")

        breaker = MagicMock()
        breaker.allow_request.return_value = True
        pool._breakers["R3"] = breaker

        with pytest.raises(ConnectionError, match="after 3 attempts"):
            await pool._with_retries(factory, "R3")

        assert pool._stats["connections_failed"] == 1
        assert breaker.record_failure.call_count == 3


# ---------------------------------------------------------------------------
# Exponential backoff
# ---------------------------------------------------------------------------

class TestExponentialBackoff:
    @pytest.mark.asyncio
    async def test_delay_increases_exponentially(self):
        """With fixed jitter=0, delays should strictly increase."""
        pool = ConnectionPool(
            max_per_device=3,
            max_idle_seconds=300,
            max_age_seconds=600,
            max_retries=3,
            base_delay=0.1,  # Large enough to dominate jitter
        )
        attempt = 0
        recorded_delays = []

        async def factory():
            nonlocal attempt
            attempt += 1
            if attempt < 3:
                raise ConnectionError("fail")
            return "ok"

        breaker = MagicMock()
        breaker.allow_request.return_value = True
        pool._breakers["R4"] = breaker

        async def capturing_sleep(delay):
            recorded_delays.append(delay)

        with patch("core.connection_pool.asyncio.sleep", side_effect=capturing_sleep), \
             patch("core.connection_pool.random.uniform", return_value=0.0):
            await pool._with_retries(factory, "R4")

        assert len(recorded_delays) == 2
        # base_delay=0.1: attempt 0 → 0.1 * 1 = 0.1, attempt 1 → 0.1 * 2 = 0.2
        assert recorded_delays[0] == pytest.approx(0.1)
        assert recorded_delays[1] == pytest.approx(0.2)
        assert recorded_delays[0] < recorded_delays[1]


# ---------------------------------------------------------------------------
# Circuit breaker integration
# ---------------------------------------------------------------------------

class TestCircuitBreakerIntegration:
    @pytest.mark.asyncio
    async def test_circuit_open_skips_retries(self, pool):
        call_count = 0

        async def factory():
            nonlocal call_count
            call_count += 1
            return "should not reach"

        breaker = MagicMock()
        breaker.allow_request.return_value = False  # Circuit is OPEN
        pool._breakers["R5"] = breaker

        with pytest.raises(ConnectionError, match="Circuit breaker open"):
            await pool._with_retries(factory, "R5")

        assert call_count == 0  # Never called the factory
        assert pool._stats["connections_failed"] == 1

    @pytest.mark.asyncio
    async def test_circuit_opens_after_threshold(self, pool):
        """Breaker records failures; after threshold, allow_request returns False."""
        attempt = 0

        async def factory():
            nonlocal attempt
            attempt += 1
            raise ConnectionError("fail")

        # Real-ish breaker mock that opens after 3 failures
        breaker = MagicMock()
        failure_count = 0

        def mock_allow():
            return failure_count < 3

        def mock_record_failure():
            nonlocal failure_count
            failure_count += 1

        breaker.allow_request = mock_allow
        breaker.record_failure = mock_record_failure
        pool._breakers["R6"] = breaker

        with pytest.raises(ConnectionError, match="after 3 attempts"):
            await pool._with_retries(factory, "R6")

        assert failure_count == 3


# ---------------------------------------------------------------------------
# Stats tracking
# ---------------------------------------------------------------------------

class TestStatsTracking:
    @pytest.mark.asyncio
    async def test_stats_include_retry_counters(self, pool):
        stats = pool.get_stats()
        assert "connections_failed" in stats
        assert "connections_retried" in stats
        assert stats["connections_failed"] == 0
        assert stats["connections_retried"] == 0
