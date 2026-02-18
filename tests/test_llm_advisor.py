"""
Tests for Phase 4: Hybrid LLM Reasoning.

Tests:
- LLMAdvisor prompt construction, response parsing, rate limiting
- DecisionEngine LLM fallback when KB confidence < threshold
- Validator intent validation for LLM-sourced decisions
"""

import asyncio
import json
import os
import time
from unittest.mock import AsyncMock, MagicMock, patch, PropertyMock

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
    import agents.reasoning.llm_advisor as llm_mod
    import agents.reasoning.decision_engine as engine_mod
    import agents.validation.validator as val_mod
    import agents.events as events_mod
    import agents.db.models as models_mod
    import agents.config as config_mod

    llm_mod._advisor = None
    engine_mod._engine = None
    val_mod._validator = None
    events_mod._bus = None
    models_mod._db = None
    config_mod._config = None
    yield
    llm_mod._advisor = None
    engine_mod._engine = None
    val_mod._validator = None
    events_mod._bus = None
    models_mod._db = None
    config_mod._config = None


def _make_llm_response(
    diagnosis="Interface down due to cable fault",
    confidence=0.7,
    risk=35,
    tool_name="health_check",
    params=None,
    reasoning="Cable fault analysis",
):
    """Build a mock LLM JSON response."""
    return json.dumps({
        "diagnosis": diagnosis,
        "confidence": confidence,
        "risk_assessment": risk,
        "proposed_action": {
            "tool_name": tool_name,
            "parameters": params or {},
            "expected_outcome": "Issue diagnosed",
        },
        "reasoning": reasoning,
    })


def _make_event(
    device="R4",
    symptom="interface_down",
    category="interface",
    severity="high",
):
    from agents.db.models import PerceivedEvent, SymptomCategory

    return PerceivedEvent.create(
        source="health_check",
        device=device,
        symptom=symptom,
        symptom_category=SymptomCategory(category),
        severity=severity,
        raw_data={"interface": "GigabitEthernet1"},
    )


# ===========================================================================
# LLMAdvisor unit tests
# ===========================================================================

class TestLLMAdvisorPrompt:
    """Test prompt construction and response parsing."""

    def test_build_prompt_includes_event_data(self):
        with patch("agents.reasoning.llm_advisor.get_config") as mock_cfg:
            cfg = MagicMock()
            cfg.llm_enabled = True
            cfg.llm_model = "claude-sonnet-4-5-20250929"
            cfg.llm_min_kb_confidence = 0.5
            mock_cfg.return_value = cfg

            from agents.reasoning.llm_advisor import LLMAdvisor

            advisor = LLMAdvisor()
            prompt = advisor._build_prompt(
                event_data={
                    "device": "R4",
                    "symptom": "interface_down",
                    "severity": "high",
                    "symptom_category": "interface",
                    "raw_data": {"interface": "Gi1"},
                },
            )

            assert "R4" in prompt
            assert "interface_down" in prompt
            assert "high" in prompt

    def test_build_prompt_truncates_long_raw_data(self):
        with patch("agents.reasoning.llm_advisor.get_config") as mock_cfg:
            cfg = MagicMock()
            cfg.llm_enabled = True
            mock_cfg.return_value = cfg

            from agents.reasoning.llm_advisor import LLMAdvisor

            advisor = LLMAdvisor()
            prompt = advisor._build_prompt(
                event_data={
                    "device": "R4",
                    "symptom": "test",
                    "severity": "high",
                    "symptom_category": "interface",
                    "raw_data": {"data": "x" * 2000},
                },
            )

            # Raw data should be truncated
            assert len(prompt) < 3000

    def test_parse_valid_json_response(self):
        with patch("agents.reasoning.llm_advisor.get_config") as mock_cfg:
            mock_cfg.return_value = MagicMock()

            from agents.reasoning.llm_advisor import LLMAdvisor

            advisor = LLMAdvisor()
            raw = _make_llm_response()
            result = advisor._parse_and_validate(raw)

            assert result is not None
            assert result["diagnosis"] == "Interface down due to cable fault"
            assert result["confidence"] == 0.7
            assert result["risk_assessment"] == 35

    def test_parse_json_with_code_fences(self):
        with patch("agents.reasoning.llm_advisor.get_config") as mock_cfg:
            mock_cfg.return_value = MagicMock()

            from agents.reasoning.llm_advisor import LLMAdvisor

            advisor = LLMAdvisor()
            raw = "```json\n" + _make_llm_response() + "\n```"
            result = advisor._parse_and_validate(raw)

            assert result is not None

    def test_parse_rejects_missing_keys(self):
        with patch("agents.reasoning.llm_advisor.get_config") as mock_cfg:
            mock_cfg.return_value = MagicMock()

            from agents.reasoning.llm_advisor import LLMAdvisor

            advisor = LLMAdvisor()
            result = advisor._parse_and_validate('{"diagnosis": "test"}')

            assert result is None

    def test_parse_rejects_non_json(self):
        with patch("agents.reasoning.llm_advisor.get_config") as mock_cfg:
            mock_cfg.return_value = MagicMock()

            from agents.reasoning.llm_advisor import LLMAdvisor

            advisor = LLMAdvisor()
            result = advisor._parse_and_validate("This is not JSON at all")

            assert result is None

    def test_confidence_clamped_to_range(self):
        with patch("agents.reasoning.llm_advisor.get_config") as mock_cfg:
            mock_cfg.return_value = MagicMock()

            from agents.reasoning.llm_advisor import LLMAdvisor

            advisor = LLMAdvisor()
            raw = _make_llm_response(confidence=1.5, risk=150)
            result = advisor._parse_and_validate(raw)

            assert result is not None
            assert result["confidence"] == 1.0
            assert result["risk_assessment"] == 100


class TestLLMAdvisorRateLimit:
    """Test LLM call rate limiting."""

    def test_rate_limit_blocks_after_max(self):
        with patch("agents.reasoning.llm_advisor.get_config") as mock_cfg:
            mock_cfg.return_value = MagicMock()

            from agents.reasoning.llm_advisor import LLMAdvisor, MAX_LLM_CALLS_PER_HOUR

            advisor = LLMAdvisor()

            # Fill up the rate limit
            for _ in range(MAX_LLM_CALLS_PER_HOUR):
                assert advisor._check_rate_limit() is True

            # Next call should be blocked
            assert advisor._check_rate_limit() is False

    def test_rate_limit_resets_after_hour(self):
        with patch("agents.reasoning.llm_advisor.get_config") as mock_cfg:
            mock_cfg.return_value = MagicMock()

            from agents.reasoning.llm_advisor import LLMAdvisor, MAX_LLM_CALLS_PER_HOUR

            advisor = LLMAdvisor()

            # Add old timestamps (>1 hour ago)
            old_time = time.time() - 3700
            for _ in range(MAX_LLM_CALLS_PER_HOUR):
                advisor._call_timestamps.append(old_time)

            # Should still allow new calls (old ones pruned)
            assert advisor._check_rate_limit() is True


class TestLLMAdvisorSanitization:
    """Test command sanitization on LLM-proposed actions."""

    def test_sanitize_rejects_disallowed_tool(self):
        with patch("agents.reasoning.llm_advisor.get_config") as mock_cfg:
            mock_cfg.return_value = MagicMock()

            from agents.reasoning.llm_advisor import LLMAdvisor

            advisor = LLMAdvisor()
            result = advisor._sanitize_action({
                "tool_name": "reload_device",
                "parameters": {},
            })

            assert result is None

    def test_sanitize_rejects_unsafe_commands(self):
        with patch("agents.reasoning.llm_advisor.get_config") as mock_cfg:
            mock_cfg.return_value = MagicMock()

            from agents.reasoning.llm_advisor import LLMAdvisor

            advisor = LLMAdvisor()
            result = advisor._sanitize_action({
                "tool_name": "send_config",
                "parameters": {"commands": ["write erase"]},
            })

            assert result is None

    def test_sanitize_allows_safe_action(self):
        with patch("agents.reasoning.llm_advisor.get_config") as mock_cfg:
            mock_cfg.return_value = MagicMock()

            from agents.reasoning.llm_advisor import LLMAdvisor

            advisor = LLMAdvisor()
            result = advisor._sanitize_action({
                "tool_name": "health_check",
                "parameters": {"device": "R4"},
            })

            assert result is not None
            assert result["tool_name"] == "health_check"


class TestLLMAdvisorDiagnose:
    """Test the full diagnose() flow with mocked API."""

    @pytest.mark.asyncio
    async def test_diagnose_returns_validated_result(self):
        with patch("agents.reasoning.llm_advisor.get_config") as mock_cfg:
            cfg = MagicMock()
            cfg.llm_enabled = True
            cfg.llm_model = "claude-sonnet-4-5-20250929"
            mock_cfg.return_value = cfg

            from agents.reasoning.llm_advisor import LLMAdvisor

            advisor = LLMAdvisor()

            # Mock the Anthropic client
            mock_response = MagicMock()
            mock_response.content = [MagicMock(text=_make_llm_response())]
            mock_client = MagicMock()
            mock_client.messages.create.return_value = mock_response
            advisor._client = mock_client

            result = await advisor.diagnose(
                event_data={
                    "device": "R4",
                    "symptom": "interface_down",
                    "severity": "high",
                    "symptom_category": "interface",
                    "raw_data": {},
                },
            )

            assert result is not None
            assert result["source"] == "llm"
            assert result["diagnosis"] == "Interface down due to cable fault"

    @pytest.mark.asyncio
    async def test_diagnose_returns_none_when_disabled(self):
        with patch("agents.reasoning.llm_advisor.get_config") as mock_cfg:
            cfg = MagicMock()
            cfg.llm_enabled = False
            mock_cfg.return_value = cfg

            from agents.reasoning.llm_advisor import LLMAdvisor

            advisor = LLMAdvisor()
            result = await advisor.diagnose(event_data={"device": "R4"})

            assert result is None

    @pytest.mark.asyncio
    async def test_diagnose_flags_high_risk_for_human(self):
        with patch("agents.reasoning.llm_advisor.get_config") as mock_cfg:
            cfg = MagicMock()
            cfg.llm_enabled = True
            cfg.llm_model = "claude-sonnet-4-5-20250929"
            mock_cfg.return_value = cfg

            from agents.reasoning.llm_advisor import LLMAdvisor

            advisor = LLMAdvisor()

            # High-risk response
            mock_response = MagicMock()
            mock_response.content = [MagicMock(text=_make_llm_response(risk=55))]
            mock_client = MagicMock()
            mock_client.messages.create.return_value = mock_response
            advisor._client = mock_client

            result = await advisor.diagnose(
                event_data={"device": "R4", "symptom": "test", "severity": "high",
                            "symptom_category": "interface", "raw_data": {}},
            )

            assert result is not None
            assert result["requires_human_review"] is True

    @pytest.mark.asyncio
    async def test_diagnose_rejects_unsafe_llm_commands(self):
        with patch("agents.reasoning.llm_advisor.get_config") as mock_cfg:
            cfg = MagicMock()
            cfg.llm_enabled = True
            cfg.llm_model = "claude-sonnet-4-5-20250929"
            mock_cfg.return_value = cfg

            from agents.reasoning.llm_advisor import LLMAdvisor

            advisor = LLMAdvisor()

            # LLM proposes unsafe command
            mock_response = MagicMock()
            mock_response.content = [MagicMock(
                text=_make_llm_response(tool_name="send_config", params={"commands": ["write erase"]})
            )]
            mock_client = MagicMock()
            mock_client.messages.create.return_value = mock_response
            advisor._client = mock_client

            result = await advisor.diagnose(
                event_data={"device": "R4", "symptom": "test", "severity": "high",
                            "symptom_category": "interface", "raw_data": {}},
            )

            # Action should be nullified, risk escalated
            assert result is not None
            assert result["proposed_action"] is None
            assert result["risk_assessment"] >= 85


# ===========================================================================
# DecisionEngine LLM fallback tests
# ===========================================================================

class TestDecisionEngineLLMFallback:
    """Test that the decision engine falls back to LLM when KB confidence is low."""

    @pytest.mark.asyncio
    async def test_llm_fallback_triggers_on_low_kb_confidence(self):
        """When KB returns confidence < threshold and LLM is enabled, consult LLM."""
        mock_db = MagicMock()
        mock_db.get_unprocessed_events.return_value = []
        mock_db.get_pending_decisions.return_value = []
        mock_db.save_decision = MagicMock(side_effect=lambda d: d)
        mock_db.mark_event_processed = MagicMock()
        mock_db.log_audit = MagicMock()
        mock_db.get_historical_decisions = MagicMock(return_value=[])

        with (
            patch("agents.reasoning.decision_engine.get_agent_db", return_value=mock_db),
            patch("agents.reasoning.decision_engine.get_config") as mock_cfg,
            patch("agents.reasoning.decision_engine.get_event_bus") as mock_bus_fn,
        ):
            config = MagicMock()
            config.enabled = True
            config.event_poll_interval = 30
            config.min_confidence_for_action = 0.7
            config.llm_enabled = True
            config.llm_min_kb_confidence = 0.5
            config.llm_model = "claude-sonnet-4-5-20250929"
            config.get_device_override = MagicMock(return_value={"blocked_actions": []})
            mock_cfg.return_value = config

            mock_bus = MagicMock()
            mock_bus.publish = AsyncMock()
            mock_bus_fn.return_value = mock_bus

            # Mock KB to return low confidence (lazy import inside _analyze_with_kb)
            kb_instance = MagicMock()
            kb_instance.version = "1.0.0"
            kb_instance.diagnose.return_value = {
                "diagnosis": "Unknown issue",
                "confidence": 0.3,  # Below threshold
                "rule_applied": None,
                "remediation": None,
            }

            # Mock LLM advisor (lazy import inside _consult_llm)
            mock_advisor = MagicMock()
            mock_advisor.diagnose = AsyncMock(return_value={
                "diagnosis": "LLM diagnosed cable fault",
                "confidence": 0.7,
                "risk_assessment": 35,
                "proposed_action": {
                    "tool_name": "health_check",
                    "parameters": {},
                    "expected_outcome": "Diagnosed",
                },
                "reasoning": "Based on analysis",
                "source": "llm",
                "requires_human_review": False,
            })

            with (
                patch("agents.knowledge.ccie_knowledge.get_knowledge_base", return_value=kb_instance),
                patch("agents.reasoning.llm_advisor.get_llm_advisor", return_value=mock_advisor),
            ):
                from agents.reasoning.decision_engine import DecisionEngine

                engine = DecisionEngine()
                event = _make_event()

                with patch.object(engine, "_route_to_validation", new_callable=AsyncMock):
                    decision = await engine.process_event(event)

                assert decision is not None
                # Should have LLM reasoning step
                llm_steps = [
                    s for s in decision.reasoning_steps
                    if "LLM" in s.description
                ]
                assert len(llm_steps) >= 1

    @pytest.mark.asyncio
    async def test_llm_not_called_when_kb_confident(self):
        """When KB confidence >= threshold, LLM is not consulted."""
        mock_db = MagicMock()
        mock_db.get_unprocessed_events.return_value = []
        mock_db.get_pending_decisions.return_value = []
        mock_db.save_decision = MagicMock(side_effect=lambda d: d)
        mock_db.mark_event_processed = MagicMock()
        mock_db.log_audit = MagicMock()

        with (
            patch("agents.reasoning.decision_engine.get_agent_db", return_value=mock_db),
            patch("agents.reasoning.decision_engine.get_config") as mock_cfg,
            patch("agents.reasoning.decision_engine.get_event_bus") as mock_bus_fn,
        ):
            config = MagicMock()
            config.enabled = True
            config.event_poll_interval = 30
            config.min_confidence_for_action = 0.7
            config.llm_enabled = True
            config.llm_min_kb_confidence = 0.5
            config.get_device_override = MagicMock(return_value={"blocked_actions": []})
            mock_cfg.return_value = config

            mock_bus = MagicMock()
            mock_bus.publish = AsyncMock()
            mock_bus_fn.return_value = mock_bus

            # Mock KB with high confidence
            kb_instance = MagicMock()
            kb_instance.version = "1.0.0"
            kb_instance.diagnose.return_value = {
                "diagnosis": "Interface admin down",
                "confidence": 0.9,  # Above threshold
                "rule_applied": "interface_admin_down",
                "remediation": {
                    "action_type": "playbook_execute",
                    "tool_name": "playbook_execute",
                    "parameters": {"playbook_id": "interface_enable", "dry_run": True},
                    "expected_outcome": "Interface enabled",
                },
            }

            with patch("agents.knowledge.ccie_knowledge.get_knowledge_base", return_value=kb_instance):
                from agents.reasoning.decision_engine import DecisionEngine

                engine = DecisionEngine()
                event = _make_event()

                with patch.object(engine, "_route_to_validation", new_callable=AsyncMock):
                    # If LLM was consulted, it would be via lazy import
                    with patch("agents.reasoning.llm_advisor.get_llm_advisor") as mock_llm_fn:
                        decision = await engine.process_event(event)
                        # LLM get_llm_advisor should NOT have been called
                        mock_llm_fn.assert_not_called()

                assert decision is not None


# ===========================================================================
# Validator intent validation tests
# ===========================================================================

class TestValidatorIntentCheck:
    """Test intent validation for LLM-sourced decisions."""

    @pytest.mark.asyncio
    async def test_llm_decision_gets_intent_check(self):
        """LLM-sourced decisions trigger intent validation."""
        from agents.db.models import (
            AgentDecision, ProposedAction, ReasoningStep, SymptomCategory,
        )

        decision = AgentDecision.create(
            device="R4",
            symptom="interface_down",
            symptom_category=SymptomCategory.INTERFACE,
            triggering_event_id="evt-1",
            reasoning_steps=[
                ReasoningStep(step_number=1, description="KB check"),
                ReasoningStep(
                    step_number=2,
                    description="LLM advisor consulted",
                    outputs={"source": "llm", "llm_confidence": 0.7},
                ),
            ],
            knowledge_base_version="1.0.0",
            proposed_action=ProposedAction(
                action_type="health_check",
                tool_name="health_check",
                parameters={},
                expected_outcome="test",
            ),
            risk_score=30,
            confidence=0.7,
        )

        mock_db = MagicMock()
        mock_db.update_decision_status = MagicMock()
        mock_db.log_audit = MagicMock()
        mock_db.get_pending_approvals = MagicMock(return_value=[])
        mock_db.save_approval = MagicMock()

        with (
            patch("agents.validation.validator.get_agent_db", return_value=mock_db),
            patch("agents.validation.validator.get_config") as mock_cfg,
            patch("agents.validation.validator.get_event_bus") as mock_bus_fn,
            patch("agents.validation.validator.BlastRadiusCalculator") as MockCalc,
        ):
            config = MagicMock()
            config.validation_thresholds = MagicMock(
                auto_approve_max=50, human_required_min=80,
                senior_required_min=90, timeout_minutes=60,
            )
            config.is_in_change_freeze.return_value = False
            config.get_device_override.return_value = {"blocked_actions": []}
            mock_cfg.return_value = config

            mock_bus = MagicMock()
            mock_bus.create_publish_token.return_value = "token"
            mock_bus.publish = AsyncMock()
            mock_bus_fn.return_value = mock_bus

            calc = AsyncMock()
            calc.calculate.return_value = {
                "affected_routes": 0, "affected_neighbors": 0,
                "risk_category": "NO_IMPACT",
                "ospf_neighbors_lost": [], "bgp_peers_lost": [],
                "routes_removed": [], "warnings": [], "data_quality": "estimated",
            }
            MockCalc.return_value = calc

            # Mock intent_validate at its source module (lazy import in _check_llm_intent)
            with patch("mcp_tools.impact.intent_validate", new_callable=AsyncMock) as mock_intent:
                mock_intent.return_value = json.dumps({
                    "valid": True, "status": "aligned",
                })

                from agents.validation.validator import ValidationAgent

                validator = ValidationAgent()
                result = await validator.validate(decision)

                # Intent check should have been called
                mock_intent.assert_called_once()

    @pytest.mark.asyncio
    async def test_non_llm_decision_skips_intent_check(self):
        """Non-LLM decisions don't trigger intent validation."""
        from agents.db.models import (
            AgentDecision, ProposedAction, ReasoningStep, SymptomCategory,
        )

        decision = AgentDecision.create(
            device="R4",
            symptom="interface_down",
            symptom_category=SymptomCategory.INTERFACE,
            triggering_event_id="evt-1",
            reasoning_steps=[
                ReasoningStep(step_number=1, description="KB check"),
            ],
            knowledge_base_version="1.0.0",
            proposed_action=ProposedAction(
                action_type="investigate",
                tool_name="health_check",
                parameters={},
                expected_outcome="test",
            ),
            risk_score=10,
            confidence=0.8,
        )

        mock_db = MagicMock()
        mock_db.update_decision_status = MagicMock()
        mock_db.log_audit = MagicMock()

        with (
            patch("agents.validation.validator.get_agent_db", return_value=mock_db),
            patch("agents.validation.validator.get_config") as mock_cfg,
            patch("agents.validation.validator.get_event_bus") as mock_bus_fn,
            patch("agents.validation.validator.BlastRadiusCalculator") as MockCalc,
        ):
            config = MagicMock()
            config.validation_thresholds = MagicMock(
                auto_approve_max=50, human_required_min=80,
                senior_required_min=90, timeout_minutes=60,
            )
            config.is_in_change_freeze.return_value = False
            config.get_device_override.return_value = {"blocked_actions": []}
            mock_cfg.return_value = config

            mock_bus = MagicMock()
            mock_bus.create_publish_token.return_value = "token"
            mock_bus.publish = AsyncMock()
            mock_bus_fn.return_value = mock_bus

            calc = AsyncMock()
            calc.calculate.return_value = {
                "affected_routes": 0, "affected_neighbors": 0,
                "risk_category": "NO_IMPACT",
                "ospf_neighbors_lost": [], "bgp_peers_lost": [],
                "routes_removed": [], "warnings": [], "data_quality": "estimated",
            }
            MockCalc.return_value = calc

            from agents.validation.validator import ValidationAgent

            validator = ValidationAgent()

            # No intent check should be made (no mock needed)
            result = await validator.validate(decision)

            # Should have passed without intent check
            checks = result.checks
            intent_checks = [c for c in checks if c.get("name") == "llm_intent_validation"]
            assert len(intent_checks) == 0
