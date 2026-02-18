"""
Flask Application Factory.

Creates and configures the Flask app with all extensions and blueprints.
Extracted from api_server.py to support proper factory pattern.
"""

import os
import sys
import uuid
import time
import logging
from functools import wraps
from pathlib import Path

from flask import Flask, jsonify, request, g

# Ensure project root and dashboard dir are on the path
sys.path.insert(0, str(Path(__file__).parent.parent))  # Project root

from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)


def create_app(config=None):
    """Create and configure the Flask application.

    Args:
        config: Optional dict of config overrides (e.g. {'TESTING': True}).

    Returns:
        Configured Flask app instance.
    """
    app = Flask(__name__, static_folder='build', static_url_path='')

    if config:
        app.config.update(config)

    # Configure logging
    from dashboard.logging_config import configure_logging
    configure_logging(app)

    # Initialize extensions (CORS, limiter, cache, socketio)
    from dashboard.extensions import init_extensions
    init_extensions(app)

    # Register custom error handlers for APIError hierarchy
    from core.errors import register_error_handlers
    register_error_handlers(app)

    # Initialize auth database
    from dashboard.auth import init_database
    init_database()

    # Register blueprints
    _register_blueprints(app)

    # Register middleware
    _register_middleware(app)

    # Register global error handlers
    _register_error_handlers(app)

    # Apply caching to specific endpoints (must be after cache + blueprint init)
    _apply_caching(app)

    # OpenAPI/Swagger (optional)
    _init_swagger(app)

    return app


def _register_blueprints(app):
    """Register all route blueprints."""
    # Health checks
    from dashboard.routes.health import health_bp
    app.register_blueprint(health_bp)

    # Auth
    from dashboard.routes.auth_routes import auth_bp
    app.register_blueprint(auth_bp)

    # Apply auth rate limit
    from dashboard.extensions import limiter
    rate_limit_auth = os.getenv('RATE_LIMIT_AUTH', '10 per minute')
    limiter.limit(rate_limit_auth)(auth_bp)

    # Core route blueprints (decorators applied directly in each file)
    from dashboard.routes.changes import changes_bp
    app.register_blueprint(changes_bp)

    from dashboard.routes.topology import topology_bp
    app.register_blueprint(topology_bp)

    from dashboard.routes.network_tools import network_tools_bp
    limiter.limit("100 per minute")(network_tools_bp)
    app.register_blueprint(network_tools_bp)

    from dashboard.routes.telemetry import telemetry_bp
    app.register_blueprint(telemetry_bp)

    from dashboard.routes.chat import chat_bp
    app.register_blueprint(chat_bp)

    from dashboard.routes.admin import admin_bp
    app.register_blueprint(admin_bp)

    from dashboard.routes.devices import devices_bp
    app.register_blueprint(devices_bp)

    from dashboard.routes.provision import provision_bp
    app.register_blueprint(provision_bp)

    from dashboard.routes.network_ops import network_ops_bp
    app.register_blueprint(network_ops_bp)

    # Apply rate limiting to command endpoint
    rate_limit_commands = os.getenv('RATE_LIMIT_COMMANDS', '60 per minute')
    if 'network_ops.run_command' in app.view_functions:
        app.view_functions['network_ops.run_command'] = limiter.limit(rate_limit_commands)(
            app.view_functions['network_ops.run_command']
        )

    from dashboard.routes.interfaces import interfaces_bp
    app.register_blueprint(interfaces_bp)

    from dashboard.routes.impact import impact_bp
    app.register_blueprint(impact_bp)

    # Alerts (AlertManager webhook receiver)
    from dashboard.routes.alerts import alerts_bp
    app.register_blueprint(alerts_bp)

    # New extracted blueprints
    from dashboard.routes.events import events_bp
    app.register_blueprint(events_bp)

    from dashboard.routes.cache_routes import cache_bp
    app.register_blueprint(cache_bp)

    from dashboard.routes.metrics_routes import metrics_bp
    app.register_blueprint(metrics_bp)

    # Limiter exemptions for metrics/health
    limiter.exempt(health_bp)

    from dashboard.routes.spa import spa_bp
    app.register_blueprint(spa_bp)


def _register_middleware(app):
    """Register request tracking and security middleware."""
    from dashboard.lifecycle import increment_active_requests, decrement_active_requests

    @app.before_request
    def before_request_tracking():
        """Track request start and assign request ID."""
        increment_active_requests()
        g.request_id = request.headers.get('X-Request-ID', str(uuid.uuid4())[:8])
        g.start_time = time.time()

    @app.after_request
    def after_request_tracking(response):
        """Log request completion with timing and add security headers."""
        decrement_active_requests()

        duration_ms = 0
        if hasattr(g, 'start_time'):
            duration_ms = (time.time() - g.start_time) * 1000

        if hasattr(g, 'request_id'):
            response.headers['X-Request-ID'] = g.request_id

        log_level = logging.WARNING if response.status_code >= 400 else logging.INFO
        if request.path in ['/healthz', '/readyz', '/metrics']:
            log_level = logging.DEBUG

        logger.log(
            log_level,
            f"{request.method} {request.path} -> {response.status_code} ({duration_ms:.1f}ms)",
            extra={
                'request_id': getattr(g, 'request_id', 'unknown'),
                'method': request.method,
                'endpoint': request.path,
                'status_code': response.status_code,
                'duration_ms': round(duration_ms, 2),
                'remote_addr': request.remote_addr,
                'user': getattr(g, 'current_user', None),
            }
        )

        # Security headers
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        response.headers['Content-Security-Policy'] = (
            "default-src 'self'; script-src 'self'; "
            "style-src 'self' 'unsafe-inline'; "
            "connect-src 'self' ws://localhost:5001 wss://localhost:5001"
        )

        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'

        return response


def _register_error_handlers(app):
    """Register global exception handler."""

    @app.errorhandler(Exception)
    def handle_exception(e):
        logger.exception(
            f"Unhandled exception: {str(e)}",
            extra={
                'request_id': getattr(g, 'request_id', 'unknown'),
                'method': request.method,
                'endpoint': request.path,
                'remote_addr': request.remote_addr,
            }
        )
        return jsonify({
            'error': 'Internal server error',
            'request_id': getattr(g, 'request_id', 'unknown'),
        }), 500


def _apply_caching(app):
    """Apply response caching to specific read-only endpoints."""
    from dashboard.extensions import cache

    # Network Operations: Cache read-only status endpoints
    cached_network_ops = [
        'network_ops.get_bgp_summary', 'network_ops.get_ospf_neighbors',
        'network_ops.get_ospf_interfaces', 'network_ops.get_ospf_routes',
        'network_ops.get_ospf_status',
    ]
    for endpoint_name in cached_network_ops:
        if endpoint_name in app.view_functions:
            timeout = 30 if endpoint_name == 'network_ops.get_ospf_status' else 45
            app.view_functions[endpoint_name] = cache.cached(
                timeout=timeout, query_string=True
            )(app.view_functions[endpoint_name])

    # Interface Routes: Cache status endpoints
    cached_interfaces = [
        'interfaces.get_interface_stats', 'interfaces.get_dmvpn_status',
        'interfaces.get_switch_status',
    ]
    for endpoint_name in cached_interfaces:
        if endpoint_name in app.view_functions:
            timeout = 20 if 'get_interface_stats' in endpoint_name else 45
            app.view_functions[endpoint_name] = cache.cached(
                timeout=timeout, query_string=True
            )(app.view_functions[endpoint_name])


def _init_swagger(app):
    """Initialize OpenAPI/Swagger documentation if available."""
    try:
        from flasgger import Swagger
        from dashboard.openapi_spec import SWAGGER_TEMPLATE, SWAGGER_CONFIG
        Swagger(app, template=SWAGGER_TEMPLATE, config=SWAGGER_CONFIG)
    except ImportError:
        pass
