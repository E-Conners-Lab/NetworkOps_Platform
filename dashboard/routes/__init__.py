"""
Route blueprints for the NetworkOps API.

This package contains modular Flask blueprints, extracted from the monolithic
api_server.py to improve separation of concerns and maintainability.
"""

from .health import health_bp
from .auth_routes import auth_bp
from .alerts import alerts_bp
from .changes import changes_bp
from .topology import topology_bp
from .network_tools import network_tools_bp
from .telemetry import telemetry_bp
from .chat import chat_bp
from .admin import admin_bp
from .devices import devices_bp
from .network_ops import network_ops_bp
from .interfaces import interfaces_bp

__all__ = ['health_bp', 'auth_bp', 'alerts_bp', 'changes_bp', 'topology_bp', 'network_tools_bp', 'telemetry_bp', 'chat_bp', 'admin_bp', 'devices_bp', 'network_ops_bp', 'interfaces_bp']
