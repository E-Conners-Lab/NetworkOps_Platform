"""
Tests for Phase 3: Escalation & Multi-Strategy Remediation.

Tests:
- EscalationManager chains, dry-run promotion, chain exhaustion
- ExecutionLoop escalation after failure and dry-run promotion
- BlastRadiusCalculator coordinated impact detection
- CCIE Knowledge Base escalation_chain passthrough
"""

import asyncio
import os
import sqlite3
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# --- CI env bootstrap (same as conftest.py) ---
os.environ.setdefault("JWT_SECRET_KEY", "test-secret-key-for-ci")
os.environ.setdefault("FLASK_SECRET_KEY", "test-flask-secret")
os.environ.setdefault("SINGLE_SESSION_ENABLED", "false")


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def _reset_singletons():
    """Reset global singletons between tests."""
    import agents.execution.escalation as esc_mod
    import agents.execution.execution_loop as loop_mod
    import agents.events as events_mod
    import agents.db.models as models_mod

    esc_mod._manager = None
    loop_mod._loop = None
    events_mod._bus = None
    models_mod._db = None
    yield
    esc_mod._manager = None
    loop_mod._loop = None
    events_mod._bus = None
    models_mod._db = None


@pytest.fixture
def mock_db():
    """Provide a mock AgentDatabase."""
    db = MagicMock()
    db.save_decision = MagicMock(side_effect=lambda d: d)
    db.get_decision = MagicMock(return_value=None)
    db.log_audit = MagicMock()
    db.get_decisions_by_status = MagicMock(return_value=[])
    db.update_decision_status = MagicMock()
    return db


def _make_decision(
    device="R1",
    symptom="interface_down",
    category="interface",
    action_type="playbook_execute",
    tool_name="playbook_execute",
    params=None,
    escalation_level=0,
    parent_decision_id=None,
    confidence=0.8,
    risk_score=30,
    trace_id="trace-1",
):
    """Helper to create a test AgentDecision."""
    from agents.db.models import (
        AgentDecision,
        ProposedAction,
        ReasoningStep,
        SymptomCategory,
    )

    return AgentDecision.create(
        device=device,
        symptom=symptom,
        symptom_category=SymptomCategory(category),
        triggering_event_id="evt-1",
        reasoning_steps=[ReasoningStep(step_number=1, description="test")],
        knowledge_base_version="1.0.0",
        proposed_action=ProposedAction(
            action_type=action_type,
            tool_name=tool_name,
            parameters=params or {"playbook_id": "interface_bounce"},
            expected_outcome="test",
            rollback_available=True,
        ),
        risk_score=risk_score,
        confidence=confidence,
        trace_id=trace_id,
        parent_decision_id=parent_decision_id,
        escalation_level=escalation_level,
    )


# ===========================================================================
# EscalationManager tests
# ===========================================================================

class TestEscalationManager:
    """Test the EscalationManager escalation chain logic."""

    def test_get_next_strategy_returns_next_level(self, mock_db):
        with patch("agents.execution.escalation.get_agent_db", return_value=mock_db):
            from agents.execution.escalation import EscalationManager

            mgr = EscalationManager()
            decision = _make_decision(escalation_level=0)

            child = mgr.get_next_strategy(decision)

            assert child is not None
            assert child.escalation_level == 1
            assert child.parent_decision_id == decision.id
            # Level 1 in interface chain: playbook_execute dry-run
            assert child.proposed_action.parameters.get("dry_run") is True

    def test_get_next_strategy_exhausted(self, mock_db):
        with patch("agents.execution.escalation.get_agent_db", return_value=mock_db):
            from agents.execution.escalation import EscalationManager

            mgr = EscalationManager()
            # Interface chain has 4 entries (0-3), so level 3 is the last
            decision = _make_decision(escalation_level=3)

            child = mgr.get_next_strategy(decision)

            assert child is None

    def test_get_next_strategy_alert_at_end(self, mock_db):
        with patch("agents.execution.escalation.get_agent_db", return_value=mock_db):
            from agents.execution.escalation import EscalationManager

            mgr = EscalationManager()
            # Level 2 → next is level 3 which is alert
            decision = _make_decision(escalation_level=2)

            child = mgr.get_next_strategy(decision)

            assert child is not None
            assert child.proposed_action.action_type == "alert"
            assert child.proposed_action.tool_name == "send_notification"

    def test_get_next_strategy_confidence_decay(self, mock_db):
        with patch("agents.execution.escalation.get_agent_db", return_value=mock_db):
            from agents.execution.escalation import EscalationManager

            mgr = EscalationManager()
            decision = _make_decision(confidence=0.8, escalation_level=0)

            child = mgr.get_next_strategy(decision)

            assert child is not None
            assert child.confidence == pytest.approx(0.72, abs=0.01)  # 0.8 * 0.9

    def test_get_next_strategy_unknown_category(self, mock_db):
        with patch("agents.execution.escalation.get_agent_db", return_value=mock_db):
            from agents.execution.escalation import EscalationManager

            mgr = EscalationManager()
            # Use a real category that has a chain (routing has only 2 entries)
            decision = _make_decision(
                category="routing", escalation_level=1
            )

            child = mgr.get_next_strategy(decision)

            # Routing chain has 2 entries (0-1), so level 1 is the last
            assert child is None

    def test_dry_run_followup(self, mock_db):
        with patch("agents.execution.escalation.get_agent_db", return_value=mock_db):
            from agents.execution.escalation import EscalationManager

            mgr = EscalationManager()
            decision = _make_decision(
                params={"playbook_id": "interface_bounce", "dry_run": True},
                escalation_level=1,
            )

            followup = mgr.get_dry_run_followup(decision)

            assert followup is not None
            assert followup.proposed_action.parameters["dry_run"] is False
            assert followup.parent_decision_id == decision.id
            assert followup.escalation_level == 1  # Same level

    def test_dry_run_followup_not_dry_run(self, mock_db):
        with patch("agents.execution.escalation.get_agent_db", return_value=mock_db):
            from agents.execution.escalation import EscalationManager

            mgr = EscalationManager()
            decision = _make_decision(
                params={"playbook_id": "interface_bounce"},
            )

            followup = mgr.get_dry_run_followup(decision)

            assert followup is None


# ===========================================================================
# ExecutionLoop escalation integration tests
# ===========================================================================

class TestExecutionLoopEscalation:
    """Test escalation and dry-run promotion in the execution loop."""

    @pytest.mark.asyncio
    async def test_escalation_on_failure(self, mock_db):
        """Failed execution triggers escalation to next strategy."""
        with (
            patch("agents.execution.execution_loop.get_agent_db", return_value=mock_db),
            patch("agents.execution.execution_loop.get_config") as mock_cfg,
            patch("agents.execution.execution_loop.get_rate_limiter") as mock_rl,
            patch("agents.execution.execution_loop.get_tool_executor") as mock_exec,
            patch("agents.execution.execution_loop.get_escalation_manager") as mock_esc,
        ):
            config = MagicMock()
            config.autonomous_execution = True
            mock_cfg.return_value = config

            rl = MagicMock()
            rl.can_execute.return_value = (True, "")
            rl.record_execution = MagicMock()
            rl.record_failure = MagicMock()
            rl.record_success = MagicMock()
            rl.get_device_lock.return_value = asyncio.Lock()
            mock_rl.return_value = rl

            executor = AsyncMock()
            executor.execute.return_value = {"status": "error", "error": "tool failed"}
            mock_exec.return_value = executor

            child_decision = _make_decision(escalation_level=1)
            escalation = MagicMock()
            escalation.get_next_strategy.return_value = child_decision
            escalation.get_dry_run_followup.return_value = None
            mock_esc.return_value = escalation

            from agents.execution.execution_loop import ExecutionLoop

            loop = ExecutionLoop()
            decision = _make_decision(escalation_level=0)

            await loop._execute_with_timeout(decision)

            # Escalation should have been called
            escalation.get_next_strategy.assert_called_once_with(decision)
            # Child decision should be saved
            mock_db.save_decision.assert_called_once_with(child_decision)

    @pytest.mark.asyncio
    async def test_dry_run_promotion_on_success(self, mock_db):
        """Successful dry-run triggers promotion to live execution."""
        with (
            patch("agents.execution.execution_loop.get_agent_db", return_value=mock_db),
            patch("agents.execution.execution_loop.get_config") as mock_cfg,
            patch("agents.execution.execution_loop.get_rate_limiter") as mock_rl,
            patch("agents.execution.execution_loop.get_tool_executor") as mock_exec,
            patch("agents.execution.execution_loop.get_escalation_manager") as mock_esc,
        ):
            config = MagicMock()
            config.autonomous_execution = True
            mock_cfg.return_value = config

            rl = MagicMock()
            rl.can_execute.return_value = (True, "")
            rl.record_execution = MagicMock()
            rl.record_success = MagicMock()
            rl.get_device_lock.return_value = asyncio.Lock()
            mock_rl.return_value = rl

            executor = AsyncMock()
            executor.execute.return_value = {"status": "success"}
            mock_exec.return_value = executor

            followup = _make_decision(
                params={"playbook_id": "interface_bounce", "dry_run": False}
            )
            escalation = MagicMock()
            escalation.get_next_strategy.return_value = None
            escalation.get_dry_run_followup.return_value = followup
            mock_esc.return_value = escalation

            from agents.execution.execution_loop import ExecutionLoop

            loop = ExecutionLoop()
            decision = _make_decision(
                params={"playbook_id": "interface_bounce", "dry_run": True}
            )

            await loop._execute_with_timeout(decision)

            # Dry-run promotion should have been called
            escalation.get_dry_run_followup.assert_called_once_with(decision)
            mock_db.save_decision.assert_called_once_with(followup)

    @pytest.mark.asyncio
    async def test_no_escalation_on_chain_exhausted(self, mock_db):
        """When chain is exhausted, no new decision is created."""
        with (
            patch("agents.execution.execution_loop.get_agent_db", return_value=mock_db),
            patch("agents.execution.execution_loop.get_config") as mock_cfg,
            patch("agents.execution.execution_loop.get_rate_limiter") as mock_rl,
            patch("agents.execution.execution_loop.get_tool_executor") as mock_exec,
            patch("agents.execution.execution_loop.get_escalation_manager") as mock_esc,
        ):
            config = MagicMock()
            config.autonomous_execution = True
            mock_cfg.return_value = config

            rl = MagicMock()
            rl.can_execute.return_value = (True, "")
            rl.record_execution = MagicMock()
            rl.record_failure = MagicMock()
            rl.get_device_lock.return_value = asyncio.Lock()
            mock_rl.return_value = rl

            executor = AsyncMock()
            executor.execute.return_value = {"status": "error"}
            mock_exec.return_value = executor

            escalation = MagicMock()
            escalation.get_next_strategy.return_value = None  # Exhausted
            escalation.get_dry_run_followup.return_value = None
            mock_esc.return_value = escalation

            from agents.execution.execution_loop import ExecutionLoop

            loop = ExecutionLoop()
            decision = _make_decision(escalation_level=3)

            await loop._execute_with_timeout(decision)

            # No new decision saved
            mock_db.save_decision.assert_not_called()


# ===========================================================================
# BlastRadiusCalculator coordinated impact tests
# ===========================================================================

class TestCoordinatedImpact:
    """Test coordinated impact detection for overlapping blast radii."""

    @pytest.mark.asyncio
    async def test_no_overlap_for_single_decision(self):
        from agents.validation.blast_radius import BlastRadiusCalculator

        calc = BlastRadiusCalculator()
        d1 = _make_decision(device="R1")

        result = await calc.calculate_coordinated_impact([d1])

        assert result["overlap_detected"] is False
        assert result["stagger_recommended"] is False

    @pytest.mark.asyncio
    async def test_overlap_same_device(self):
        from agents.validation.blast_radius import BlastRadiusCalculator

        calc = BlastRadiusCalculator()
        d1 = _make_decision(device="R1")
        d2 = _make_decision(device="R1")

        with patch.object(calc, "calculate", new_callable=AsyncMock) as mock_calc:
            mock_calc.return_value = {
                "affected_routes": 5,
                "ospf_neighbors_lost": [],
                "bgp_peers_lost": [],
            }

            result = await calc.calculate_coordinated_impact([d1, d2])

        assert result["overlap_detected"] is True
        assert result["stagger_recommended"] is True
        assert len(result["overlaps"]) == 1
        assert result["overlaps"][0]["same_device"] is True

    @pytest.mark.asyncio
    async def test_overlap_shared_neighbors(self):
        from agents.validation.blast_radius import BlastRadiusCalculator

        calc = BlastRadiusCalculator()
        d1 = _make_decision(device="R1")
        d2 = _make_decision(device="R2")

        call_count = 0

        async def mock_calc(decision):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return {
                    "affected_routes": 5,
                    "ospf_neighbors_lost": ["R3", "R4"],
                    "bgp_peers_lost": [],
                }
            return {
                "affected_routes": 3,
                "ospf_neighbors_lost": ["R3"],
                "bgp_peers_lost": [],
            }

        with patch.object(calc, "calculate", side_effect=mock_calc):
            result = await calc.calculate_coordinated_impact([d1, d2])

        assert result["overlap_detected"] is True
        assert len(result["overlaps"]) == 1
        assert "R3" in result["overlaps"][0]["shared_ospf_neighbors"]

    @pytest.mark.asyncio
    async def test_no_overlap_different_devices_no_shared(self):
        from agents.validation.blast_radius import BlastRadiusCalculator

        calc = BlastRadiusCalculator()
        d1 = _make_decision(device="R1")
        d2 = _make_decision(device="R6")

        call_count = 0

        async def mock_calc(decision):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return {
                    "affected_routes": 2,
                    "ospf_neighbors_lost": ["R2"],
                    "bgp_peers_lost": [],
                }
            return {
                "affected_routes": 1,
                "ospf_neighbors_lost": ["R7"],
                "bgp_peers_lost": [],
            }

        with patch.object(calc, "calculate", side_effect=mock_calc):
            result = await calc.calculate_coordinated_impact([d1, d2])

        assert result["overlap_detected"] is False
        assert result["stagger_recommended"] is False


# ===========================================================================
# CCIE Knowledge Base escalation_chain passthrough tests
# ===========================================================================

class TestKnowledgeBaseEscalationChain:
    """Test that escalation_chain from YAML rules passes through."""

    def test_diagnose_includes_escalation_chain(self):
        from agents.db.models import SymptomCategory
        from agents.knowledge.ccie_knowledge import CCIEKnowledgeBase

        kb = CCIEKnowledgeBase()
        result = kb.diagnose(
            symptom="interface_down",
            category=SymptomCategory.INTERFACE,
            device="R1",
            context={"admin_status": "down"},
        )

        assert "escalation_chain" in result
        chain = result["escalation_chain"]
        assert len(chain) >= 3
        assert chain[0]["action_type"] == "investigate"
        assert chain[-1]["action_type"] == "alert"

    def test_diagnose_without_escalation_chain(self):
        from agents.db.models import SymptomCategory
        from agents.knowledge.ccie_knowledge import CCIEKnowledgeBase

        kb = CCIEKnowledgeBase()
        # interface_errors with crc condition has no escalation_chain
        result = kb.diagnose(
            symptom="interface_errors",
            category=SymptomCategory.INTERFACE,
            device="R1",
            context={"error_type": "crc"},
        )

        assert "escalation_chain" not in result

    def test_ospf_rule_has_escalation_chain(self):
        from agents.db.models import SymptomCategory
        from agents.knowledge.ccie_knowledge import CCIEKnowledgeBase

        kb = CCIEKnowledgeBase()
        result = kb.diagnose(
            symptom="ospf_neighbor_down",
            category=SymptomCategory.OSPF,
            device="R2",
            context={"interface_status": "down"},
        )

        assert "escalation_chain" in result
        chain = result["escalation_chain"]
        assert len(chain) == 5
        # Should include both investigate and playbook steps
        action_types = [e["action_type"] for e in chain]
        assert "investigate" in action_types
        assert "playbook_execute" in action_types
        assert "alert" in action_types
