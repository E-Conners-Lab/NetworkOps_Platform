"""
Tests for Phase 6: Production Hardening.

Tests:
- Per-symptom rate limiting prevents thrashing
- SNMP poll generates valid PerceivedEvents
- SNMP poll detects high CPU, low memory, interfaces down
- SNMP poll ignores healthy devices
- Guardrail enforcement under production-like scenarios
"""

import asyncio
import json
import os
from datetime import datetime
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# --- CI env bootstrap ---
os.environ.setdefault("JWT_SECRET_KEY", "test-secret-key-for-ci")
os.environ.setdefault("FLASK_SECRET_KEY", "test-flask-secret")
os.environ.setdefault("SINGLE_SESSION_ENABLED", "false")


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def _reset_singletons():
    """Reset global singletons between tests."""
    import agents.perception.event_ingestor as ingestor_mod
    import agents.execution.rate_limiter as limiter_mod
    import agents.db.models as models_mod

    ingestor_mod._ingestor = None
    limiter_mod._limiter = None
    models_mod._db = None
    yield
    ingestor_mod._ingestor = None
    limiter_mod._limiter = None
    models_mod._db = None


# ===========================================================================
# Per-Symptom Rate Limiting Tests
# ===========================================================================

class TestPerSymptomRateLimiting:
    """Verify per-symptom rate limiting prevents thrashing on same issue."""

    def test_per_symptom_blocks_after_threshold(self):
        """Actions for same device:symptom should be blocked after max_per_symptom_per_hour."""
        from agents.execution.rate_limiter import ActionRateLimiter, RateLimiterConfig

        limiter = ActionRateLimiter(RateLimiterConfig(
            max_actions_per_hour=100,
            max_per_device_per_hour=100,
            max_per_symptom_per_hour=3,
        ))

        decision = MagicMock()
        decision.device = "R1"
        decision.symptom = "interface_down"
        decision.proposed_action.action_type = "investigate"

        # First 3 should be allowed
        for i in range(3):
            allowed, _ = limiter.can_execute(decision)
            assert allowed, f"Action {i+1} should be allowed"
            limiter.record_execution(decision)

        # 4th should be blocked
        allowed, reason = limiter.can_execute(decision)
        assert not allowed
        assert "per_symptom_limit" in reason
        assert "R1:interface_down" in reason

    def test_different_symptoms_independent(self):
        """Different symptoms on the same device should have independent limits."""
        from agents.execution.rate_limiter import ActionRateLimiter, RateLimiterConfig

        limiter = ActionRateLimiter(RateLimiterConfig(
            max_actions_per_hour=100,
            max_per_device_per_hour=100,
            max_per_symptom_per_hour=2,
        ))

        decision_if = MagicMock()
        decision_if.device = "R1"
        decision_if.symptom = "interface_down"
        decision_if.proposed_action.action_type = "investigate"

        decision_ospf = MagicMock()
        decision_ospf.device = "R1"
        decision_ospf.symptom = "ospf_neighbor_down"
        decision_ospf.proposed_action.action_type = "investigate"

        # Fill up interface_down limit
        for _ in range(2):
            limiter.record_execution(decision_if)

        # interface_down blocked
        allowed, _ = limiter.can_execute(decision_if)
        assert not allowed

        # ospf_neighbor_down still allowed
        allowed, _ = limiter.can_execute(decision_ospf)
        assert allowed

    def test_different_devices_independent(self):
        """Same symptom on different devices should have independent limits."""
        from agents.execution.rate_limiter import ActionRateLimiter, RateLimiterConfig

        limiter = ActionRateLimiter(RateLimiterConfig(
            max_actions_per_hour=100,
            max_per_device_per_hour=100,
            max_per_symptom_per_hour=2,
        ))

        decision_r1 = MagicMock()
        decision_r1.device = "R1"
        decision_r1.symptom = "interface_down"
        decision_r1.proposed_action.action_type = "investigate"

        decision_r2 = MagicMock()
        decision_r2.device = "R2"
        decision_r2.symptom = "interface_down"
        decision_r2.proposed_action.action_type = "investigate"

        # Fill up R1 limit
        for _ in range(2):
            limiter.record_execution(decision_r1)

        # R1 blocked
        allowed, _ = limiter.can_execute(decision_r1)
        assert not allowed

        # R2 still allowed
        allowed, _ = limiter.can_execute(decision_r2)
        assert allowed


# ===========================================================================
# SNMP Polling Tests
# ===========================================================================

class TestSNMPPolling:
    """Tests for SNMP metric polling in EventIngestor."""

    def test_snmp_poll_high_cpu_creates_event(self):
        """SNMP poll should create a high_cpu event when CPU > 80%."""
        from agents.perception.event_ingestor import EventIngestor

        with patch("agents.db.models.DatabaseManager") as mock_cls:
            mock_cls.get_instance.return_value = MagicMock()
            ingestor = EventIngestor()

        # Mock the DB save
        ingestor._db = MagicMock()
        ingestor._db.save_event = MagicMock(side_effect=lambda e: e)

        snmp_result = {
            "results": [
                {
                    "device": "R1",
                    "success": True,
                    "cpu": 92,
                    "memory": {"used_percent": 50},
                    "interfaces_down": 0,
                }
            ]
        }

        with patch("mcp_tools.snmp.snmp_poll_all_devices", new_callable=AsyncMock) as mock_snmp:
            mock_snmp.return_value = json.dumps(snmp_result)

            asyncio.get_event_loop().run_until_complete(
                ingestor._poll_snmp_metrics()
            )

        # Should have saved one event (high_cpu)
        assert ingestor._db.save_event.call_count == 1
        saved_event = ingestor._db.save_event.call_args[0][0]
        assert saved_event.symptom == "high_cpu"
        assert saved_event.device == "R1"
        assert saved_event.severity == "high"  # >90%

    def test_snmp_poll_low_memory_creates_event(self):
        """SNMP poll should create low_memory event when memory > 85%."""
        from agents.perception.event_ingestor import EventIngestor

        with patch("agents.db.models.DatabaseManager") as mock_cls:
            mock_cls.get_instance.return_value = MagicMock()
            ingestor = EventIngestor()

        ingestor._db = MagicMock()
        ingestor._db.save_event = MagicMock(side_effect=lambda e: e)

        snmp_result = {
            "results": [
                {
                    "device": "R2",
                    "success": True,
                    "cpu": 30,
                    "memory": {"used_percent": 88},
                    "interfaces_down": 0,
                }
            ]
        }

        with patch("mcp_tools.snmp.snmp_poll_all_devices", new_callable=AsyncMock) as mock_snmp:
            mock_snmp.return_value = json.dumps(snmp_result)

            asyncio.get_event_loop().run_until_complete(
                ingestor._poll_snmp_metrics()
            )

        assert ingestor._db.save_event.call_count == 1
        saved_event = ingestor._db.save_event.call_args[0][0]
        assert saved_event.symptom == "low_memory"
        assert saved_event.device == "R2"
        assert saved_event.severity == "medium"  # 85-95%

    def test_snmp_poll_interfaces_down_creates_event(self):
        """SNMP poll should create interface_down event when interfaces are down."""
        from agents.perception.event_ingestor import EventIngestor

        with patch("agents.db.models.DatabaseManager") as mock_cls:
            mock_cls.get_instance.return_value = MagicMock()
            ingestor = EventIngestor()

        ingestor._db = MagicMock()
        ingestor._db.save_event = MagicMock(side_effect=lambda e: e)

        snmp_result = {
            "results": [
                {
                    "device": "R3",
                    "success": True,
                    "cpu": 20,
                    "memory": {"used_percent": 40},
                    "interfaces_down": 2,
                }
            ]
        }

        with patch("mcp_tools.snmp.snmp_poll_all_devices", new_callable=AsyncMock) as mock_snmp:
            mock_snmp.return_value = json.dumps(snmp_result)

            asyncio.get_event_loop().run_until_complete(
                ingestor._poll_snmp_metrics()
            )

        assert ingestor._db.save_event.call_count == 1
        saved_event = ingestor._db.save_event.call_args[0][0]
        assert saved_event.symptom == "interface_down"
        assert saved_event.device == "R3"

    def test_snmp_poll_healthy_device_no_events(self):
        """SNMP poll should not create events for healthy devices."""
        from agents.perception.event_ingestor import EventIngestor

        with patch("agents.db.models.DatabaseManager") as mock_cls:
            mock_cls.get_instance.return_value = MagicMock()
            ingestor = EventIngestor()

        ingestor._db = MagicMock()
        ingestor._db.save_event = MagicMock(side_effect=lambda e: e)

        snmp_result = {
            "results": [
                {
                    "device": "R4",
                    "success": True,
                    "cpu": 15,
                    "memory": {"used_percent": 40},
                    "interfaces_down": 0,
                }
            ]
        }

        with patch("mcp_tools.snmp.snmp_poll_all_devices", new_callable=AsyncMock) as mock_snmp:
            mock_snmp.return_value = json.dumps(snmp_result)

            asyncio.get_event_loop().run_until_complete(
                ingestor._poll_snmp_metrics()
            )

        assert ingestor._db.save_event.call_count == 0

    def test_snmp_poll_failed_device_skipped(self):
        """SNMP poll should skip devices that failed to respond."""
        from agents.perception.event_ingestor import EventIngestor

        with patch("agents.db.models.DatabaseManager") as mock_cls:
            mock_cls.get_instance.return_value = MagicMock()
            ingestor = EventIngestor()

        ingestor._db = MagicMock()
        ingestor._db.save_event = MagicMock(side_effect=lambda e: e)

        snmp_result = {
            "results": [
                {
                    "device": "R6",
                    "success": False,
                    "error": "SNMP timeout",
                }
            ]
        }

        with patch("mcp_tools.snmp.snmp_poll_all_devices", new_callable=AsyncMock) as mock_snmp:
            mock_snmp.return_value = json.dumps(snmp_result)

            asyncio.get_event_loop().run_until_complete(
                ingestor._poll_snmp_metrics()
            )

        assert ingestor._db.save_event.call_count == 0

    def test_snmp_poll_multiple_issues_same_device(self):
        """SNMP poll should create multiple events for a device with multiple issues."""
        from agents.perception.event_ingestor import EventIngestor

        with patch("agents.db.models.DatabaseManager") as mock_cls:
            mock_cls.get_instance.return_value = MagicMock()
            ingestor = EventIngestor()

        ingestor._db = MagicMock()
        ingestor._db.save_event = MagicMock(side_effect=lambda e: e)

        snmp_result = {
            "results": [
                {
                    "device": "R7",
                    "success": True,
                    "cpu": 95,
                    "memory": {"used_percent": 96},
                    "interfaces_down": 1,
                }
            ]
        }

        with patch("mcp_tools.snmp.snmp_poll_all_devices", new_callable=AsyncMock) as mock_snmp:
            mock_snmp.return_value = json.dumps(snmp_result)

            asyncio.get_event_loop().run_until_complete(
                ingestor._poll_snmp_metrics()
            )

        # Should have 3 events: high_cpu, low_memory, interface_down
        assert ingestor._db.save_event.call_count == 3
        symptoms = [call[0][0].symptom for call in ingestor._db.save_event.call_args_list]
        assert "high_cpu" in symptoms
        assert "low_memory" in symptoms
        assert "interface_down" in symptoms


# ===========================================================================
# Guardrail Enforcement Under Load
# ===========================================================================

class TestGuardrailsUnderLoad:
    """Test that safety guardrails hold under production-like scenarios."""

    def test_emergency_stop_overrides_all(self):
        """Emergency stop should block all executions regardless of other limits."""
        from agents.execution.rate_limiter import ActionRateLimiter, RateLimiterConfig

        limiter = ActionRateLimiter(RateLimiterConfig(max_actions_per_hour=100))

        decision = MagicMock()
        decision.device = "R1"
        decision.symptom = "interface_down"
        decision.proposed_action.action_type = "investigate"

        # Normal: allowed
        allowed, _ = limiter.can_execute(decision)
        assert allowed

        # Activate emergency stop
        limiter.emergency_stop()

        # Now blocked
        allowed, reason = limiter.can_execute(decision)
        assert not allowed
        assert "emergency_stop" in reason

        # Resume
        limiter.emergency_resume()
        allowed, _ = limiter.can_execute(decision)
        assert allowed

    def test_circuit_breaker_resets_after_success(self):
        """Circuit breaker should reset failure count after a success."""
        from agents.execution.rate_limiter import ActionRateLimiter, RateLimiterConfig

        limiter = ActionRateLimiter(RateLimiterConfig(
            circuit_breaker_threshold=3,
            cooldown_after_failure=1,  # Short for testing
        ))

        # 2 failures (just under threshold)
        limiter.record_failure()
        limiter.record_failure()

        # Success resets
        limiter.record_success()

        # 2 more failures (still under threshold because of reset)
        limiter.record_failure()
        limiter.record_failure()

        assert limiter._consecutive_failures == 2
        assert limiter._circuit_open_until == 0.0  # Breaker not tripped

    def test_per_device_lock_exists(self):
        """Per-device locks should be unique per device."""
        from agents.execution.rate_limiter import ActionRateLimiter

        limiter = ActionRateLimiter()

        lock_r1 = limiter.get_device_lock("R1")
        lock_r2 = limiter.get_device_lock("R2")
        lock_r1_again = limiter.get_device_lock("R1")

        assert lock_r1 is lock_r1_again  # Same device, same lock
        assert lock_r1 is not lock_r2  # Different devices, different locks
        assert isinstance(lock_r1, asyncio.Lock)
