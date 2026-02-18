"""
Network Topology Dashboard API Server.

Entry point that creates the Flask app via the application factory.
Backward-compatible re-exports are provided for modules that import from here.
"""

import sys
from pathlib import Path

# Ensure project root and dashboard dir are on the path
sys.path.insert(0, str(Path(__file__).parent.parent))  # Project root

from dashboard.app import create_app
from dashboard.extensions import socketio, cache

# Create the application
app = create_app()

# ---------------------------------------------------------------------------
# Backward-compatible re-exports
# Modules in dashboard/routes/ import these names from api_server.
# Over time, these should be replaced with direct imports from their sources.
# ---------------------------------------------------------------------------
from core import log_event  # noqa: F401
from config.devices import is_containerlab_device, is_linux_device, DEVICES, DEVICE_HOSTS  # noqa: F401
from core.containerlab import run_command as run_containerlab_command  # noqa: F401
from security.command_policy import (  # noqa: F401
    validate_command,
    BLOCKED_COMMANDS,
    BLOCKED_SHELL_CHARS,
    OPERATOR_ALLOWED_PREFIXES,
)
from core.topology_helpers import (  # noqa: F401
    is_config_command,
    invalidate_device_cache,
    discover_topology,
)
from dashboard.mdt_collector import get_mdt_collector, telemetry_data  # noqa: F401

mdt_collector = get_mdt_collector(port=57000)

# TELEMETRY_IP_MAP: reverse lookup from management IP -> device name
TELEMETRY_IP_MAP = {v: k for k, v in DEVICE_HOSTS.items()}  # noqa: F401

# Password change enforcement (OWASP A07:2021) — re-exported for tests
import os as _os  # noqa: E402
from functools import wraps as _wraps  # noqa: E402
from flask import g as _g, jsonify as _jsonify  # noqa: E402
from dashboard.auth import check_password_change_required as _check_pwd  # noqa: E402

ENFORCE_PASSWORD_CHANGE = _os.getenv("ENFORCE_PASSWORD_CHANGE", "true").lower() == "true"  # noqa: F401


def password_change_check(f):  # noqa: F401
    """Block access if user needs to change password (except allowed endpoints)."""
    @_wraps(f)
    def decorated(*args, **kwargs):
        if not ENFORCE_PASSWORD_CHANGE:
            return f(*args, **kwargs)
        if hasattr(_g, 'current_user') and _g.current_user:
            if _check_pwd(_g.current_user):
                return _jsonify({
                    "error": "Password change required",
                    "code": "PASSWORD_CHANGE_REQUIRED",
                    "message": "You must change your default password before accessing this resource"
                }), 403
        return f(*args, **kwargs)
    return decorated


if __name__ == '__main__':
    import os
    import logging
    from dashboard.lifecycle import register_shutdown_handlers
    from dashboard.routes.metrics_routes import start_device_metrics_collector

    logger = logging.getLogger('networkops')

    # Register graceful shutdown handlers
    register_shutdown_handlers()

    # Start MDT collector for real-time telemetry
    mdt_external = os.getenv('MDT_EXTERNAL', 'false').lower() == 'true'
    if not mdt_external:
        logger.info("Starting MDT collector on gRPC port 57000...")
        mdt_collector.start()
    else:
        logger.info("MDT_EXTERNAL=true, starting Redis pub/sub bridge...")
        from dashboard.telemetry_ws_bridge import start_telemetry_ws_bridge
        start_telemetry_ws_bridge(socketio)

    # Start device metrics collector for Prometheus
    logger.info("Starting device metrics collector (30-second polling)...")
    start_device_metrics_collector()

    # Set up WebSocket telemetry callbacks
    from dashboard.routes.websocket import register_websocket_handlers, setup_telemetry_callbacks
    register_websocket_handlers(socketio, telemetry_data)
    setup_telemetry_callbacks(socketio, telemetry_data)

    logger.info("Starting Network Topology API Server on port 5001 (with WebSocket)...")
    logger.info(f"  - Log format: {os.getenv('LOG_FORMAT', 'json')}")
    logger.info(f"  - Log level: {os.getenv('LOG_LEVEL', 'INFO')}")

    # Disable reloader to avoid gRPC fork issues
    socketio.run(app, host='0.0.0.0', port=5001, debug=False, use_reloader=False, allow_unsafe_werkzeug=(os.getenv('FLASK_ENV') != 'production'))  # nosec B104
