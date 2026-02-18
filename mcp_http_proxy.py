"""Simple HTTP proxy for MCP tools.

Run this alongside the main API server to expose MCP tools via HTTP.
This allows external clients like NetBot to call MCP tools.

Usage:
    python mcp_http_proxy.py

Then NetBot can use: NETBOT_MCP_ENDPOINT=http://localhost:5002
"""

import asyncio
import os
from flask import Flask, jsonify, request
from flask_cors import CORS
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

# Auth imports
from security.tool_auth import (
    MCP_AUTH_ENABLED,
    set_auth_from_token,
    clear_auth_context,
)
from security.token_validator import validate_token

# Import MCP tools
from mcp_tools.device import get_devices, send_command, health_check
from mcp_tools.config import backup_config, list_backups
from mcp_tools.operations import (
    get_routing_table,
    get_arp_table,
    get_neighbors,
    get_interface_status,
    ping_sweep,
    traceroute,
)
from mcp_tools.testing import (
    pyats_snapshot_state,
    pyats_diff_state,
    pyats_list_baselines,
    pyats_learn_feature,
    pyats_cve_check,
    pyats_interface_report,
    pyats_inventory_report,
    aetest_run_tests,
    aetest_list_tests,
    aetest_run_suite,
)
from mcp_tools.compliance import (
    compliance_check,
    compliance_check_all,
)

app = Flask(__name__)

# CORS configuration
_cors_origins = os.getenv("MCP_CORS_ORIGINS")
if _cors_origins is None:
    # Default: permissive when auth disabled, restrictive when enabled
    if MCP_AUTH_ENABLED:
        _cors_origins = ""  # No origins allowed unless explicitly configured
    else:
        _cors_origins = "*"

if _cors_origins == "*":
    CORS(app)
elif _cors_origins:
    CORS(app, origins=_cors_origins.split(","))
# else: no CORS headers at all (all cross-origin requests rejected)


# =============================================================================
# Auth Middleware
# =============================================================================

@app.before_request
def _authenticate_request():
    """Extract and validate Bearer token, set auth context.

    When MCP_AUTH_ENABLED is false, this is a no-op.
    /health is always exempt.
    """
    if not MCP_AUTH_ENABLED:
        return None

    # Health endpoint is always public
    if request.path == "/health":
        return None

    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return jsonify({"error": "Missing or invalid Authorization header"}), 401

    token = auth_header[7:]
    payload = validate_token(token)
    if payload is None:
        return jsonify({"error": "Invalid or expired token"}), 401

    # Set auth context for this request
    set_auth_from_token(payload)
    return None


@app.teardown_request
def _clear_auth(exc=None):
    """Clear auth context after each request."""
    if MCP_AUTH_ENABLED:
        clear_auth_context()


from dashboard.utils.async_helpers import run_async_with_context as run_async


@app.route('/health')
def health():
    return jsonify({"status": "ok"})


@app.route('/tools/get_devices', methods=['POST'])
def api_get_devices():
    try:
        # get_devices is a sync function, call directly
        result = get_devices()
        return jsonify({"result": result})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/tools/send_command', methods=['POST'])
def api_send_command():
    try:
        data = request.json or {}
        device_name = data.get('device_name')
        command = data.get('command')
        if not device_name or not command:
            return jsonify({"error": "Missing device_name or command"}), 400
        result = run_async(send_command(device_name, command))
        return jsonify({"result": result})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/tools/health_check', methods=['POST'])
def api_health_check():
    try:
        data = request.json or {}
        device_name = data.get('device_name')
        if not device_name:
            return jsonify({"error": "Missing device_name"}), 400
        result = run_async(health_check(device_name))
        return jsonify({"result": result})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/tools/get_routing_table', methods=['POST'])
def api_get_routing_table():
    try:
        data = request.json or {}
        device_name = data.get('device_name')
        protocol = data.get('protocol')
        prefix = data.get('prefix')
        if not device_name:
            return jsonify({"error": "Missing device_name"}), 400
        result = run_async(get_routing_table(device_name, protocol, prefix))
        return jsonify({"result": result})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/tools/get_arp_table', methods=['POST'])
def api_get_arp_table():
    try:
        data = request.json or {}
        device_name = data.get('device_name')
        vrf = data.get('vrf')
        if not device_name:
            return jsonify({"error": "Missing device_name"}), 400
        result = run_async(get_arp_table(device_name, vrf))
        return jsonify({"result": result})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/tools/get_neighbors', methods=['POST'])
def api_get_neighbors():
    try:
        data = request.json or {}
        device_name = data.get('device_name')
        protocol = data.get('protocol', 'cdp')
        if not device_name:
            return jsonify({"error": "Missing device_name"}), 400
        result = run_async(get_neighbors(device_name, protocol))
        return jsonify({"result": result})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/tools/get_interface_status', methods=['POST'])
def api_get_interface_status():
    try:
        data = request.json or {}
        device_name = data.get('device_name')
        interface = data.get('interface')
        if not device_name or not interface:
            return jsonify({"error": "Missing device_name or interface"}), 400
        result = run_async(get_interface_status(device_name, interface))
        return jsonify({"result": result})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/tools/ping_sweep', methods=['POST'])
def api_ping_sweep():
    try:
        data = request.json or {}
        device_name = data.get('device_name')
        targets = data.get('targets')
        count = data.get('count', 2)
        if not device_name or not targets:
            return jsonify({"error": "Missing device_name or targets"}), 400
        result = run_async(ping_sweep(device_name, targets, count))
        return jsonify({"result": result})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/tools/traceroute', methods=['POST'])
def api_traceroute():
    try:
        data = request.json or {}
        device_name = data.get('device_name')
        destination = data.get('destination')
        source = data.get('source')
        if not device_name or not destination:
            return jsonify({"error": "Missing device_name or destination"}), 400
        result = run_async(traceroute(device_name, destination, source))
        return jsonify({"result": result})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# =============================================================================
# pyATS Testing Endpoints
# =============================================================================

@app.route('/tools/pyats_snapshot_state', methods=['POST'])
def api_pyats_snapshot_state():
    try:
        data = request.json or {}
        device_name = data.get('device_name')
        label = data.get('label', 'baseline')
        if not device_name:
            return jsonify({"error": "Missing device_name"}), 400
        result = run_async(pyats_snapshot_state(device_name, label))
        return jsonify({"result": result})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/tools/pyats_diff_state', methods=['POST'])
def api_pyats_diff_state():
    try:
        data = request.json or {}
        device_name = data.get('device_name')
        label = data.get('label', 'baseline')
        if not device_name:
            return jsonify({"error": "Missing device_name"}), 400
        result = run_async(pyats_diff_state(device_name, label))
        return jsonify({"result": result})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/tools/pyats_list_baselines', methods=['POST'])
def api_pyats_list_baselines():
    try:
        result = run_async(pyats_list_baselines())
        return jsonify({"result": result})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/tools/pyats_learn_feature', methods=['POST'])
def api_pyats_learn_feature():
    try:
        data = request.json or {}
        device_name = data.get('device_name')
        feature = data.get('feature')
        if not device_name or not feature:
            return jsonify({"error": "Missing device_name or feature"}), 400
        result = run_async(pyats_learn_feature(device_name, feature))
        return jsonify({"result": result})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/tools/pyats_cve_check', methods=['POST'])
def api_pyats_cve_check():
    try:
        data = request.json or {}
        device_name = data.get('device_name')  # Can be None for all devices
        result = run_async(pyats_cve_check(device_name))
        return jsonify({"result": result})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/tools/pyats_interface_report', methods=['POST'])
def api_pyats_interface_report():
    try:
        data = request.json or {}
        device_name = data.get('device_name')  # Can be None for all devices
        top_n = data.get('top_n', 10)
        result = run_async(pyats_interface_report(device_name, top_n))
        return jsonify({"result": result})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/tools/pyats_inventory_report', methods=['POST'])
def api_pyats_inventory_report():
    try:
        data = request.json or {}
        device_name = data.get('device_name')  # Can be None for all devices
        result = run_async(pyats_inventory_report(device_name))
        return jsonify({"result": result})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# =============================================================================
# aetest Testing Endpoints
# =============================================================================

@app.route('/tools/aetest_run_tests', methods=['POST'])
def api_aetest_run_tests():
    try:
        data = request.json or {}
        device_name = data.get('device_name')
        tests = data.get('tests', '')
        if not device_name:
            return jsonify({"error": "Missing device_name"}), 400
        result = run_async(aetest_run_tests(device_name, tests))
        return jsonify({"result": result})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/tools/aetest_list_tests', methods=['POST'])
def api_aetest_list_tests():
    try:
        result = run_async(aetest_list_tests())
        return jsonify({"result": result})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/tools/aetest_run_suite', methods=['POST'])
def api_aetest_run_suite():
    try:
        data = request.json or {}
        devices = data.get('devices')
        tests = data.get('tests', '')
        if not devices:
            return jsonify({"error": "Missing devices"}), 400
        result = run_async(aetest_run_suite(devices, tests))
        return jsonify({"result": result})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# =============================================================================
# Compliance Endpoints
# =============================================================================

@app.route('/tools/compliance_check', methods=['POST'])
def api_compliance_check():
    try:
        data = request.json or {}
        device_name = data.get('device_name')
        template = data.get('template', 'security-baseline')
        if not device_name:
            return jsonify({"error": "Missing device_name"}), 400
        result = run_async(compliance_check(device_name, template))
        return jsonify({"result": result})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/tools/compliance_check_all', methods=['POST'])
def api_compliance_check_all():
    try:
        data = request.json or {}
        template = data.get('template', 'security-baseline')
        devices = data.get('devices', '')
        result = run_async(compliance_check_all(template, devices))
        return jsonify({"result": result})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == '__main__':
    print("Starting MCP HTTP Proxy on port 5002...")
    print("NetBot can now use: export NETBOT_MCP_ENDPOINT=http://localhost:5002")
    if MCP_AUTH_ENABLED:
        print("Auth: ENABLED (Bearer token required)")
    else:
        print("Auth: DISABLED (set MCP_AUTH_ENABLED=false was explicitly set)")
    app.run(host='0.0.0.0', port=5002, debug=False)
