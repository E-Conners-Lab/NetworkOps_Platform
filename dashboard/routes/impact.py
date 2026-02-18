"""
Impact Analysis API Routes.

Pre-change impact analysis, intent validation, and dependency graph
endpoints for understanding network state, drift, and blast radius.
"""

import asyncio
import logging
from flask import Blueprint, jsonify, request, g
from core.errors import safe_error_response, ValidationError
from dashboard.auth import jwt_required, permission_required

logger = logging.getLogger(__name__)

impact_bp = Blueprint('impact', __name__, url_prefix='/api/impact')


def get_current_user():
    """Get the current user from Flask g context."""
    return g.current_user if hasattr(g, 'current_user') else 'anonymous'


from dashboard.utils.async_helpers import run_async


# =============================================================================
# Impact Analysis Endpoints
# =============================================================================


@impact_bp.route('/analyze', methods=['POST'])
@jwt_required
def analyze_impact():
    """
    Analyze the impact of an interface shutdown command.

    Request body:
    {
        "device": "R1",
        "interface": "GigabitEthernet1",
        "command": "shutdown",
        "refresh_data": true  (optional, default: true)
    }

    Returns:
    {
        "status": "completed|unsupported|insufficient_data|timeout|rate_limited|no_impact|error",
        "analysis_id": "ia-abc123",
        "device": "R1",
        "interface": "GigabitEthernet1",
        "command": "shutdown",
        "risk_category": "NO_IMPACT|LOW|MEDIUM|HIGH|CRITICAL",
        "current_state": { ... },
        "impact": { ... },
        "data_quality": { ... },
        "warnings": [],
        "analysis_duration_ms": 850
    }
    """
    try:
        from core.impact_analyzer import ImpactAnalyzer
        from config.readonly_credentials import get_readonly_credentials
        from core.feature_flags import get_impact_analysis_config

        # Check feature flag
        config = get_impact_analysis_config()
        if not config.get("enabled", False):
            return jsonify({
                "status": "unsupported",
                "reason": "Impact analysis feature is disabled",
                "how_to_enable": "Set FF_IMPACT_ANALYSIS_ENABLED=true or enable in config/feature_flags.yaml"
            }), 501

        data = request.get_json(silent=True)
        if not data:
            return jsonify({
                "status": "error",
                "reason": "No JSON data provided"
            }), 400

        # Required fields
        device = data.get('device')
        interface = data.get('interface')
        command = data.get('command')

        if not device or not interface or not command:
            return jsonify({
                "status": "error",
                "reason": "device, interface, and command are required fields"
            }), 400

        # Optional fields
        refresh_data = data.get('refresh_data', True)
        user = get_current_user()

        # Create analyzer with read-only credentials
        creds = get_readonly_credentials()
        analyzer = ImpactAnalyzer(creds)

        # Run analysis
        result = analyzer.analyze_sync(
            device=device,
            interface=interface,
            command=command,
            refresh_data=refresh_data,
            user=user
        )

        # Return appropriate HTTP status based on result
        result_dict = result.to_dict()

        if result.status.value == "rate_limited":
            return jsonify(result_dict), 429
        elif result.status.value == "timeout":
            return jsonify(result_dict), 504
        elif result.status.value == "error":
            return jsonify(result_dict), 500
        else:
            return jsonify(result_dict), 200

    except Exception as e:
        return safe_error_response(e, "analyze impact")


@impact_bp.route('/status', methods=['GET'])
@jwt_required
def get_status():
    """
    Get impact analysis feature status and configuration.

    Returns:
    {
        "enabled": true|false,
        "supported_platforms": ["cisco_xe"],
        "analysis_timeout_sec": 10,
        "data_max_age_sec": 300,
        "rate_limits": {
            "per_user_per_minute": 10,
            "per_device_per_minute": 2
        }
    }
    """
    try:
        from core.feature_flags import get_impact_analysis_config

        config = get_impact_analysis_config()

        return jsonify({
            "enabled": config.get("enabled", False),
            "supported_platforms": config.get("supported_platforms", ["cisco_xe"]),
            "analysis_timeout_sec": config.get("analysis_timeout_sec", 10),
            "data_max_age_sec": config.get("data_max_age_sec", 300),
            "rate_limits": {
                "per_user_per_minute": config.get("rate_limit_per_user_per_minute", 10),
                "per_device_per_minute": config.get("rate_limit_per_device_per_minute", 2)
            }
        }), 200

    except Exception as e:
        return safe_error_response(e, "get impact status")


@impact_bp.route('/supported-interfaces', methods=['GET'])
@jwt_required
def get_supported_interfaces():
    """
    Get information about supported interface types for impact analysis.

    Returns which interfaces are supported, unsupported, and planned
    for future phases.
    """
    from core.impact_analyzer import (
        UNSUPPORTED_INTERFACE_PATTERNS,
        MANAGEMENT_INTERFACE_PATTERNS,
    )

    return jsonify({
        "supported": {
            "description": "Physical data interfaces on Cisco IOS-XE devices",
            "examples": ["GigabitEthernet1", "GigabitEthernet2", "TenGigabitEthernet0/0/0"]
        },
        "unsupported": {
            "management": {
                "patterns": MANAGEMENT_INTERFACE_PATTERNS,
                "reason": "Management interfaces should never be shutdown remotely",
                "supported_in": None
            },
            "logical": {
                "patterns": UNSUPPORTED_INTERFACE_PATTERNS,
                "reason": "Logical interfaces require complex analysis",
                "supported_in": "Phase 4+"
            }
        },
        "planned_phases": {
            "Phase 2": ["Nokia SR Linux", "Arista EOS"],
            "Phase 3": ["VXLAN overlays", "L3VPN impact"],
            "Phase 4": ["Loopback (routing identity)", "Tunnel (DMVPN)"]
        }
    }), 200


# =============================================================================
# Trending Endpoints
# =============================================================================


@impact_bp.route('/trending/<device>/snapshots', methods=['GET'])
@jwt_required
def get_snapshots(device: str):
    """
    Get historical snapshots for a device.

    Query params:
        days: Number of days to look back (default: 7)
        limit: Maximum snapshots to return (default: 100)

    Returns:
    {
        "device": "R1",
        "count": 5,
        "snapshots": [ ... ]
    }
    """
    try:
        from config.devices import DEVICES
        from core.impact_trending import get_impact_trending

        if device not in DEVICES:
            return jsonify({
                "status": "error",
                "reason": f"Device '{device}' not found"
            }), 404

        days = max(1, min(365, request.args.get('days', 7, type=int)))
        limit = max(1, min(1000, request.args.get('limit', 100, type=int)))

        trending = get_impact_trending()
        snapshots = trending.get_snapshots(device, days=days, limit=limit)

        return jsonify({
            "device": device,
            "count": len(snapshots),
            "snapshots": [s.to_dict() for s in snapshots]
        }), 200

    except Exception as e:
        return safe_error_response(e, "get snapshots")


@impact_bp.route('/trending/<device>/snapshot', methods=['POST'])
@jwt_required
@permission_required('run_config_commands')
def capture_snapshot(device: str):
    """
    Capture current device state as a snapshot.

    Request body (optional):
    {
        "notes": "Pre-maintenance snapshot"
    }

    Returns:
    {
        "status": "success",
        "snapshot": { ... }
    }
    """
    try:
        from config.devices import DEVICES
        from core.impact_trending import get_impact_trending
        from core.feature_flags import get_impact_analysis_config

        # Check feature flag
        config = get_impact_analysis_config()
        if not config.get("enabled", False):
            return jsonify({
                "status": "error",
                "reason": "Impact analysis feature is disabled"
            }), 501

        if device not in DEVICES:
            return jsonify({
                "status": "error",
                "reason": f"Device '{device}' not found"
            }), 404

        data = request.get_json(silent=True) or {}
        notes = data.get('notes')

        trending = get_impact_trending()
        snapshot = run_async(trending.capture_snapshot(device, notes=notes))

        return jsonify({
            "status": "success",
            "snapshot": snapshot.to_dict()
        }), 201

    except Exception as e:
        return safe_error_response(e, "capture snapshot")


@impact_bp.route('/trending/<device>/baseline', methods=['GET'])
@jwt_required
def get_baseline(device: str):
    """
    Get the current baseline for a device.

    Returns:
    {
        "status": "success|no_baseline",
        "baseline": { ... } or null
    }
    """
    try:
        from config.devices import DEVICES
        from core.impact_trending import get_impact_trending

        if device not in DEVICES:
            return jsonify({
                "status": "error",
                "reason": f"Device '{device}' not found"
            }), 404

        trending = get_impact_trending()
        baseline = trending.get_baseline(device)

        if baseline is None:
            return jsonify({
                "status": "no_baseline",
                "device": device,
                "message": "No baseline set for this device"
            }), 200

        return jsonify({
            "status": "success",
            "baseline": baseline.to_dict()
        }), 200

    except Exception as e:
        return safe_error_response(e, "get baseline")


@impact_bp.route('/trending/<device>/baseline', methods=['POST'])
@jwt_required
@permission_required('run_config_commands')
def set_baseline(device: str):
    """
    Set a baseline for a device.

    Request body:
    {
        "snapshot_id": "abc123",  (optional - captures new if not provided)
        "reason": "Post-upgrade validation"  (optional)
    }

    Returns:
    {
        "status": "success",
        "baseline": { ... }
    }
    """
    try:
        from config.devices import DEVICES
        from core.impact_trending import get_impact_trending
        from core.feature_flags import get_impact_analysis_config

        # Check feature flag
        config = get_impact_analysis_config()
        if not config.get("enabled", False):
            return jsonify({
                "status": "error",
                "reason": "Impact analysis feature is disabled"
            }), 501

        if device not in DEVICES:
            return jsonify({
                "status": "error",
                "reason": f"Device '{device}' not found"
            }), 404

        data = request.get_json(silent=True) or {}
        snapshot_id = data.get('snapshot_id')
        reason = data.get('reason')
        user = get_current_user()

        trending = get_impact_trending()

        # If no snapshot_id, capture new snapshot
        if snapshot_id is None:
            snapshot = run_async(trending.capture_snapshot(device, notes="Baseline capture"))
            snapshot_id = snapshot.snapshot_id

        trending.set_baseline(device, snapshot_id, set_by=user, reason=reason)
        baseline = trending.get_baseline(device)

        return jsonify({
            "status": "success",
            "baseline": baseline.to_dict() if baseline else None
        }), 200

    except ValueError as e:
        return jsonify({
            "status": "error",
            "reason": str(e)
        }), 400
    except Exception as e:
        return safe_error_response(e, "set baseline")


@impact_bp.route('/trending/<device>/baseline', methods=['DELETE'])
@jwt_required
@permission_required('run_config_commands')
def clear_baseline(device: str):
    """
    Clear the baseline for a device.

    Returns:
    {
        "status": "success",
        "message": "Baseline cleared"
    }
    """
    try:
        from config.devices import DEVICES
        from core.impact_trending import get_impact_trending

        if device not in DEVICES:
            return jsonify({
                "status": "error",
                "reason": f"Device '{device}' not found"
            }), 404

        trending = get_impact_trending()
        trending.clear_baseline(device)

        return jsonify({
            "status": "success",
            "message": f"Baseline cleared for {device}"
        }), 200

    except Exception as e:
        return safe_error_response(e, "clear baseline")


@impact_bp.route('/trending/<device>/drift', methods=['GET'])
@jwt_required
def check_drift(device: str):
    """
    Check for drift between current state and baseline.

    Returns:
    {
        "status": "success|no_baseline|error",
        "report": {
            "total_drifts": 2,
            "critical_count": 1,
            "warning_count": 1,
            "info_count": 0,
            "drifts": [ ... ],
            "summary": "..."
        }
    }
    """
    try:
        from config.devices import DEVICES
        from core.impact_trending import get_impact_trending
        from core.feature_flags import get_impact_analysis_config

        # Check feature flag
        config = get_impact_analysis_config()
        if not config.get("enabled", False):
            return jsonify({
                "status": "error",
                "reason": "Impact analysis feature is disabled"
            }), 501

        if device not in DEVICES:
            return jsonify({
                "status": "error",
                "reason": f"Device '{device}' not found"
            }), 404

        trending = get_impact_trending()

        # Check if baseline exists
        baseline = trending.get_baseline(device)
        if baseline is None:
            return jsonify({
                "status": "no_baseline",
                "device": device,
                "message": "No baseline set. Use POST /api/impact/trending/{device}/baseline first."
            }), 200

        report = run_async(trending.compare_to_baseline(device))

        return jsonify({
            "status": "success",
            "report": report.to_dict()
        }), 200

    except Exception as e:
        return safe_error_response(e, "check drift")


@impact_bp.route('/trending/<device>/summary', methods=['GET'])
@jwt_required
def get_trending_summary(device: str):
    """
    Get trending summary for a device.

    Query params:
        days: Number of days to look back (default: 7)

    Returns:
    {
        "device": "R1",
        "period_days": 7,
        "snapshot_count": 15,
        "has_baseline": true,
        "drift_counts": { "critical": 1, "warning": 3, "info": 5 },
        "latest_state": { ... }
    }
    """
    try:
        from config.devices import DEVICES
        from core.impact_trending import get_impact_trending

        if device not in DEVICES:
            return jsonify({
                "status": "error",
                "reason": f"Device '{device}' not found"
            }), 404

        days = max(1, min(365, request.args.get('days', 7, type=int)))

        trending = get_impact_trending()
        summary = trending.get_trending_summary(device, days=days)

        return jsonify(summary), 200

    except Exception as e:
        return safe_error_response(e, "get trending summary")


@impact_bp.route('/trending/drift-history', methods=['GET'])
@jwt_required
def get_drift_history():
    """
    Get drift history across devices.

    Query params:
        device: Filter by device (optional)
        days: Number of days to look back (default: 7)
        severity: Filter by severity (critical, warning, info)
        limit: Maximum records (default: 100)

    Returns:
    {
        "count": 15,
        "drifts": [ ... ]
    }
    """
    try:
        from core.impact_trending import get_impact_trending

        device = request.args.get('device')
        days = max(1, min(365, request.args.get('days', 7, type=int)))
        severity = request.args.get('severity')
        limit = max(1, min(1000, request.args.get('limit', 100, type=int)))

        trending = get_impact_trending()
        drifts = trending.get_drift_history(
            device=device,
            days=days,
            severity=severity,
            limit=limit
        )

        return jsonify({
            "count": len(drifts),
            "drifts": drifts
        }), 200

    except Exception as e:
        return safe_error_response(e, "get drift history")


@impact_bp.route('/trending/<device>/drift-impact', methods=['GET'])
@jwt_required
def drift_with_impact(device: str):
    """
    Check for drift and trace downstream impact via dependency graph.

    Combines baseline drift detection with graph-based impact analysis
    to show not just what changed, but what's affected by the change.

    Returns:
    {
        "status": "success|no_baseline|error",
        "drift_report": { ... },
        "downstream_impact": [ ... ],
        "correlated_events": [ ... ],
        "summary": "..."
    }
    """
    try:
        from config.devices import DEVICES
        from core.impact_trending import get_impact_trending
        from core.feature_flags import get_impact_analysis_config

        config = get_impact_analysis_config()
        if not config.get("enabled", False):
            return jsonify({
                "status": "error",
                "reason": "Impact analysis feature is disabled"
            }), 501

        if device not in DEVICES:
            return jsonify({
                "status": "error",
                "reason": f"Device '{device}' not found"
            }), 404

        trending = get_impact_trending()

        baseline = trending.get_baseline(device)
        if baseline is None:
            return jsonify({
                "status": "no_baseline",
                "device": device,
                "message": "No baseline set. Use POST /api/impact/trending/{device}/baseline first."
            }), 200

        result = run_async(trending.drift_with_impact(device))

        return jsonify({
            "status": "success",
            **result,
        }), 200

    except Exception as e:
        return safe_error_response(e, "drift with impact")


# =============================================================================
# Intent Validation Endpoints
# =============================================================================

# NOTE: Static routes (/intent/health, /intent/report, /intent/definitions)
# MUST be registered before /intent/<device> so Flask doesn't match
# "health", "report", "definitions" as device names.


@impact_bp.route('/intent/health', methods=['GET'])
@jwt_required
def get_intent_health():
    """Get network-wide intent health score."""
    try:
        from core.intent_engine import get_intent_engine

        engine = get_intent_engine()
        health = engine.compute_health_score()

        return jsonify({
            "status": "success",
            **health,
        }), 200

    except Exception as e:
        return safe_error_response(e, "get intent health")


@impact_bp.route('/intent/health/<device>', methods=['GET'])
@jwt_required
def get_device_intent_health(device: str):
    """Get intent health score for a specific device."""
    try:
        from config.devices import DEVICES
        from core.intent_engine import get_intent_engine

        if device not in DEVICES:
            return jsonify({
                "status": "error",
                "reason": f"Device '{device}' not found"
            }), 404

        engine = get_intent_engine()
        health = engine.compute_health_score(device=device)

        return jsonify({
            "status": "success",
            **health,
        }), 200

    except Exception as e:
        return safe_error_response(e, "get device intent health")


@impact_bp.route('/intent/report', methods=['GET'])
@jwt_required
def get_intent_report():
    """Get consolidated network intent compliance report."""
    try:
        from core.intent_engine import get_intent_engine

        engine = get_intent_engine()
        report = engine.generate_report()

        return jsonify({
            "status": "success",
            **report,
        }), 200

    except Exception as e:
        return safe_error_response(e, "get intent report")


@impact_bp.route('/intent/definitions', methods=['GET'])
@jwt_required
def get_intent_definitions():
    """
    Get all loaded intent definitions.

    Returns:
    {
        "count": 5,
        "definitions": {
            "R1": { "role": "core-router", "ospf_neighbors": [...], ... },
            ...
        }
    }
    """
    try:
        from core.intent_engine import get_intent_engine

        engine = get_intent_engine()
        intents = engine.load_intents()

        return jsonify({
            "count": len(intents),
            "definitions": {
                name: defn.to_dict() for name, defn in intents.items()
            },
        }), 200

    except Exception as e:
        return safe_error_response(e, "get intent definitions")


@impact_bp.route('/intent/<device>', methods=['GET'])
@jwt_required
def validate_intent(device: str):
    """
    Validate a device against its YAML intent definition.

    Compares live OSPF/BGP/interface state against declared expected state.

    Returns:
    {
        "status": "success|no_intent|error",
        "device": "R3",
        "role": "edge-router",
        "total_violations": 1,
        "critical_count": 1,
        "warning_count": 0,
        "violations": [ ... ],
        "intent_summary": { ... }
    }
    """
    try:
        from config.devices import DEVICES
        from core.intent_engine import get_intent_engine
        from core.feature_flags import get_impact_analysis_config

        config = get_impact_analysis_config()
        if not config.get("enabled", False):
            return jsonify({
                "status": "error",
                "reason": "Impact analysis feature is disabled"
            }), 501

        if device not in DEVICES:
            return jsonify({
                "status": "error",
                "reason": f"Device '{device}' not found"
            }), 404

        engine = get_intent_engine()
        intent = engine.get_device_intent(device)

        if not intent:
            return jsonify({
                "status": "no_intent",
                "device": device,
                "message": f"No intent defined for {device}. "
                           "Add YAML files to data/intents/"
            }), 200

        result = run_async(engine.validate_device(device))

        return jsonify({
            "status": "success",
            "device": device,
            "role": intent.role,
            "total_violations": len(result.violations),
            "resolved_count": result.resolved_count,
            "critical_count": sum(
                1 for v in result.violations if v.violation_severity == "critical"
            ),
            "warning_count": sum(
                1 for v in result.violations if v.violation_severity == "warning"
            ),
            "violations": [v.to_dict() for v in result.violations],
            "checks": [c.to_dict() for c in result.checks],
            "intent_summary": {
                "ospf_neighbors": len(intent.ospf_neighbors),
                "bgp_peers": len(intent.bgp_peers),
                "interfaces": len(intent.interfaces),
                "routes": len(intent.routes),
            },
        }), 200

    except Exception as e:
        return safe_error_response(e, "validate intent")


@impact_bp.route('/intent', methods=['GET'])
@jwt_required
def validate_all_intents():
    """
    Validate all devices with defined intents.

    Returns:
    {
        "status": "success",
        "devices_checked": 5,
        "total_violations": 3,
        "results": {
            "R3": { "total_violations": 1, ... },
            "edge1": { "total_violations": 2, ... }
        }
    }
    """
    try:
        from core.intent_engine import get_intent_engine
        from core.feature_flags import get_impact_analysis_config

        config = get_impact_analysis_config()
        if not config.get("enabled", False):
            return jsonify({
                "status": "error",
                "reason": "Impact analysis feature is disabled"
            }), 501

        engine = get_intent_engine()
        results = run_async(engine.validate_all())

        total_violations = 0
        total_resolved = 0
        summary = {}
        for dev, result in results.items():
            total_violations += len(result.violations)
            total_resolved += result.resolved_count
            summary[dev] = {
                "total_violations": len(result.violations),
                "resolved_count": result.resolved_count,
                "critical": sum(
                    1 for v in result.violations if v.violation_severity == "critical"
                ),
                "warning": sum(
                    1 for v in result.violations if v.violation_severity == "warning"
                ),
                "violations": [v.to_dict() for v in result.violations],
                "checks": [c.to_dict() for c in result.checks],
            }

        return jsonify({
            "status": "success",
            "devices_checked": len(results),
            "total_violations": total_violations,
            "total_resolved": total_resolved,
            "results": summary,
        }), 200

    except Exception as e:
        return safe_error_response(e, "validate all intents")


@impact_bp.route('/intent/<device>/violations', methods=['GET'])
@jwt_required
def get_intent_violations(device: str):
    """
    Get stored intent violations for a device.

    Query params:
        intent_type: Filter by type (ospf_neighbor, bgp_peer, interface)
        unresolved: Show only unresolved violations (default: true)

    Returns:
    {
        "device": "R3",
        "count": 2,
        "violations": [ ... ]
    }
    """
    try:
        from config.devices import DEVICES
        from core.intent_engine import get_intent_engine

        if device not in DEVICES:
            return jsonify({
                "status": "error",
                "reason": f"Device '{device}' not found"
            }), 404

        intent_type = request.args.get('intent_type')
        unresolved = request.args.get('unresolved', 'true').lower() == 'true'

        engine = get_intent_engine()
        violations = engine.get_violations(
            device=device,
            intent_type=intent_type,
            unresolved_only=unresolved,
        )

        return jsonify({
            "device": device,
            "count": len(violations),
            "violations": violations,
        }), 200

    except Exception as e:
        return safe_error_response(e, "get intent violations")


@impact_bp.route('/intent/<device>/discover', methods=['POST'])
@jwt_required
@permission_required('run_config_commands')
def discover_intent(device: str):
    """
    Discover intents from a device's current live state.

    Returns YAML intent definitions based on what's currently running.
    """
    try:
        from config.devices import DEVICES
        from core.intent_engine import get_intent_engine
        from core.feature_flags import get_impact_analysis_config

        config = get_impact_analysis_config()
        if not config.get("enabled", False):
            return jsonify({
                "status": "error",
                "reason": "Impact analysis feature is disabled"
            }), 501

        if device not in DEVICES:
            return jsonify({
                "status": "error",
                "reason": f"Device '{device}' not found"
            }), 404

        engine = get_intent_engine()
        intent_dict = run_async(engine.discover_intents(device))
        yaml_str = engine.discover_intents_yaml(intent_dict)

        return jsonify({
            "status": "success",
            "device": device,
            "intent": intent_dict,
            "yaml": yaml_str,
            "suggested_path": f"data/intents/overrides/{device}.yaml",
        }), 200

    except Exception as e:
        return safe_error_response(e, "discover intent")


@impact_bp.route('/intent/<device>/resolve/<int:violation_id>', methods=['POST'])
@jwt_required
@permission_required('run_config_commands')
def resolve_intent_violation(device: str, violation_id: int):
    """Manually resolve an intent violation by ID."""
    try:
        from config.devices import DEVICES
        from core.intent_engine import get_intent_engine

        if device not in DEVICES:
            return jsonify({
                "status": "error",
                "reason": f"Device '{device}' not found"
            }), 404

        engine = get_intent_engine()
        resolved = engine.resolve_violation(violation_id)

        if resolved:
            return jsonify({
                "status": "success",
                "message": f"Violation {violation_id} resolved",
            }), 200
        else:
            return jsonify({
                "status": "not_found",
                "message": f"Violation {violation_id} not found or already resolved",
            }), 404

    except Exception as e:
        return safe_error_response(e, "resolve violation")


# =============================================================================
# Dependency Graph Endpoints
# =============================================================================


@impact_bp.route('/graph/build', methods=['POST'])
@jwt_required
@permission_required('run_config_commands')
def build_dependency_graph():
    """
    Build or rebuild the dependency graph from live topology data.

    Returns:
    {
        "status": "success",
        "graph": {
            "node_count": 50,
            "edge_count": 120,
            "device_count": 17,
            "devices": [ ... ],
            "edge_types": [ ... ]
        }
    }
    """
    try:
        from core.dependency_graph import NetworkDependencyGraph
        from core.feature_flags import get_impact_analysis_config

        config = get_impact_analysis_config()
        if not config.get("enabled", False):
            return jsonify({
                "status": "error",
                "reason": "Impact analysis feature is disabled"
            }), 501

        graph = NetworkDependencyGraph()
        run_async(graph.build())

        return jsonify({
            "status": "success",
            "graph": graph.to_dict(),
        }), 201

    except Exception as e:
        return safe_error_response(e, "build dependency graph")


@impact_bp.route('/graph', methods=['GET'])
@jwt_required
def get_dependency_graph():
    """
    Get the current dependency graph summary.

    Returns:
    {
        "status": "success|not_built",
        "graph": { ... }
    }
    """
    try:
        from core.dependency_graph import NetworkDependencyGraph

        graph = NetworkDependencyGraph()
        if not graph.load_latest():
            return jsonify({
                "status": "not_built",
                "message": "No dependency graph found. "
                           "Use POST /api/impact/graph/build to create one."
            }), 200

        return jsonify({
            "status": "success",
            "graph": graph.to_dict(),
        }), 200

    except Exception as e:
        return safe_error_response(e, "get dependency graph")


@impact_bp.route('/graph/forward/<device>', methods=['GET'])
@jwt_required
def forward_impact(device: str):
    """
    Analyze what breaks if a device goes down.

    Uses the dependency graph to trace all downstream effects.

    Returns:
    {
        "status": "success",
        "device": "R3",
        "affected_devices": ["edge1", "server1"],
        "direct_neighbors": ["R2", "edge1"],
        "bgp_affected": ["edge1"],
        "ospf_affected": ["R2"],
        "total_affected": 2
    }
    """
    try:
        from config.devices import DEVICES
        from core.dependency_graph import NetworkDependencyGraph
        from core.feature_flags import get_impact_analysis_config

        config = get_impact_analysis_config()
        if not config.get("enabled", False):
            return jsonify({
                "status": "error",
                "reason": "Impact analysis feature is disabled"
            }), 501

        if device not in DEVICES:
            return jsonify({
                "status": "error",
                "reason": f"Device '{device}' not found"
            }), 404

        graph = NetworkDependencyGraph()
        if not graph.load_latest():
            run_async(graph.build())

        result = graph.forward_impact(device)

        return jsonify({
            "status": "success",
            **result,
        }), 200

    except Exception as e:
        return safe_error_response(e, "forward impact analysis")


@impact_bp.route('/graph/backward/<device>', methods=['GET'])
@jwt_required
def backward_dependencies(device: str):
    """
    Analyze what must be up for a device to work.

    Uses the dependency graph to trace all upstream dependencies.

    Returns:
    {
        "status": "success",
        "device": "edge1",
        "dependencies": ["R1", "R2", "R3"],
        "direct_dependencies": ["R3"],
        "total_dependencies": 3
    }
    """
    try:
        from config.devices import DEVICES
        from core.dependency_graph import NetworkDependencyGraph
        from core.feature_flags import get_impact_analysis_config

        config = get_impact_analysis_config()
        if not config.get("enabled", False):
            return jsonify({
                "status": "error",
                "reason": "Impact analysis feature is disabled"
            }), 501

        if device not in DEVICES:
            return jsonify({
                "status": "error",
                "reason": f"Device '{device}' not found"
            }), 404

        graph = NetworkDependencyGraph()
        if not graph.load_latest():
            run_async(graph.build())

        result = graph.backward_dependencies(device)

        return jsonify({
            "status": "success",
            **result,
        }), 200

    except Exception as e:
        return safe_error_response(e, "backward dependency analysis")


@impact_bp.route('/graph/blast-radius/<device>/<path:interface>', methods=['GET'])
@jwt_required
def blast_radius(device: str, interface: str):
    """
    Calculate blast radius of a specific interface going down.

    More precise than device-level forward analysis because it only
    considers paths through the specific interface.

    Args:
        device: Device name (URL path)
        interface: Interface name (URL path, supports slashes e.g. ethernet-1/1)

    Returns:
    {
        "status": "success",
        "device": "R3",
        "interface": "GigabitEthernet4",
        "affected_devices": ["edge1", "server1"],
        "directly_connected": ["edge1"],
        "total_affected": 2
    }
    """
    try:
        from config.devices import DEVICES
        from core.dependency_graph import NetworkDependencyGraph
        from core.feature_flags import get_impact_analysis_config

        config = get_impact_analysis_config()
        if not config.get("enabled", False):
            return jsonify({
                "status": "error",
                "reason": "Impact analysis feature is disabled"
            }), 501

        if device not in DEVICES:
            return jsonify({
                "status": "error",
                "reason": f"Device '{device}' not found"
            }), 404

        graph = NetworkDependencyGraph()
        if not graph.load_latest():
            run_async(graph.build())

        result = graph.blast_radius(device, interface)

        return jsonify({
            "status": "success",
            **result,
        }), 200

    except Exception as e:
        return safe_error_response(e, "blast radius analysis")


# =============================================================================
# Unified Events Endpoint
# =============================================================================


@impact_bp.route('/events', methods=['GET'])
@jwt_required
def get_events():
    """
    Get cross-subsystem events (drift, intent, compliance, traffic).

    Query params:
        device: Filter by device (optional)
        subsystem: Filter by subsystem (drift, intent, compliance, traffic)
        severity: Filter by severity (critical, warning, info)
        days: Number of days to look back (default: 7)
        limit: Maximum records (default: 100)

    Returns:
    {
        "count": 15,
        "events": [ ... ]
    }
    """
    try:
        from core.unified_db import UnifiedDB
        from datetime import timedelta
        from core.timestamps import now

        device = request.args.get('device')
        subsystem = request.args.get('subsystem')
        severity = request.args.get('severity')
        days = max(1, min(365, request.args.get('days', 7, type=int)))
        limit = max(1, min(1000, request.args.get('limit', 100, type=int)))

        cutoff = (now() - timedelta(days=days)).isoformat()

        query = "SELECT * FROM events WHERE timestamp >= ?"
        params = [cutoff]

        if device:
            query += " AND device = ?"
            params.append(device)

        if subsystem:
            query += " AND subsystem = ?"
            params.append(subsystem)

        if severity:
            query += " AND severity = ?"
            params.append(severity)

        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)

        import sqlite3
        db = UnifiedDB.get_instance()
        with db.connect() as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(query, params).fetchall()
            events = [dict(row) for row in rows]

        return jsonify({
            "count": len(events),
            "events": events,
        }), 200

    except Exception as e:
        return safe_error_response(e, "get events")
