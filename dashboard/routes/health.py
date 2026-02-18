"""
Health check endpoints for the NetworkOps API.

Provides Kubernetes-compatible liveness, readiness, and detailed health probes.
Extracted from api_server.py to improve separation of concerns.
"""

import os
import time
import platform
import logging
from datetime import datetime, timezone
from flask import Blueprint, jsonify, request

from dashboard.auth import decode_token, get_redis_blacklist_status

logger = logging.getLogger(__name__)

# Create blueprint
health_bp = Blueprint('health', __name__)

# Redis URL for health checks
REDIS_URL = os.getenv('REDIS_URL', 'redis://localhost:6379/0')

# Redis is only critical when explicitly configured (not using the default)
_REDIS_EXPLICITLY_CONFIGURED = 'REDIS_URL' in os.environ

# Demo mode flag
_DEMO_MODE = os.getenv('DEMO_MODE', 'false').lower() == 'true'

# Feature flags
ENFORCE_PASSWORD_CHANGE = os.getenv("ENFORCE_PASSWORD_CHANGE", "true").lower() == "true"


# =============================================================================
# Health Check Helper Functions
# =============================================================================

def check_redis_health() -> tuple[bool, str]:
    """Check Redis connectivity."""
    try:
        import redis
        client = redis.from_url(REDIS_URL)
        client.ping()
        return True, "connected"
    except Exception as e:
        logger.warning(f"Redis health check failed: {e}")
        return False, "connection failed"


def check_postgres_health() -> tuple[bool, str]:
    """Check PostgreSQL connectivity."""
    try:
        from sqlalchemy import create_engine, text
        db_url = os.getenv('DATABASE_URL', 'postgresql://networkops:networkops_dev@localhost:5432/networkops')
        engine = create_engine(db_url, pool_pre_ping=True)
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        return True, "connected"
    except Exception as e:
        logger.warning(f"PostgreSQL health check failed: {e}")
        return False, "connection failed"


def check_celery_health() -> tuple[bool, str]:
    """Check Celery worker availability."""
    try:
        from core.celery_app import celery_app
        inspect = celery_app.control.inspect(timeout=2.0)
        active = inspect.active()
        if active:
            worker_count = len(active)
            return True, f"{worker_count} worker(s) active"
        return False, "no workers responding"
    except Exception as e:
        logger.warning(f"Celery health check failed: {e}")
        return False, "check failed"


# =============================================================================
# Liveness Probe
# =============================================================================

@health_bp.route('/healthz')
@health_bp.route('/health/live')
def liveness():
    """
    Liveness probe - is the process running?

    Used by Kubernetes to determine if container should be restarted.
    This endpoint is exempt from rate limiting.
    """
    return jsonify({
        "status": "ok",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "service": "networkops-api",
        "version": os.getenv("APP_VERSION", "1.2.0"),
    })


# =============================================================================
# Readiness Probe
# =============================================================================

@health_bp.route('/readyz')
@health_bp.route('/health/ready')
def readiness():
    """
    Readiness probe - is the service ready to accept traffic?

    Used by Kubernetes/load balancers to determine if traffic should be routed
    to this instance. Checks all critical dependencies before accepting traffic.
    """
    # Lazy import to avoid circular dependency
    from dashboard.mdt_collector import get_mdt_collector

    checks = {}

    # Check Redis (critical for caching)
    redis_ok, redis_msg = check_redis_health()
    checks["redis"] = {"healthy": redis_ok, "message": redis_msg}

    # Check PostgreSQL (optional - graceful degradation)
    postgres_ok, postgres_msg = check_postgres_health()
    checks["postgres"] = {"healthy": postgres_ok, "message": postgres_msg}

    # Check Celery workers (optional - sync API still works)
    celery_ok, celery_msg = check_celery_health()
    checks["celery"] = {"healthy": celery_ok, "message": celery_msg}

    # Check MDT collector
    mdt = get_mdt_collector()
    mdt_ok = mdt._running if mdt else False
    checks["mdt_collector"] = {"healthy": mdt_ok, "message": "running" if mdt_ok else "stopped"}

    # Determine overall status
    # Redis is critical only when explicitly configured via REDIS_URL env var.
    # In demo mode or default setups (no Redis), all deps are non-critical.
    redis_critical = _REDIS_EXPLICITLY_CONFIGURED and not _DEMO_MODE
    critical_ok = redis_ok if redis_critical else True
    all_ok = all(c["healthy"] for c in checks.values())

    if all_ok:
        status = "ok"
        http_status = 200
    elif critical_ok:
        status = "degraded"
        http_status = 200  # Still accept traffic, but degraded
    else:
        status = "unavailable"
        http_status = 503

    return jsonify({
        "status": status,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "checks": checks,
    }), http_status


# =============================================================================
# Detailed Health
# =============================================================================

@health_bp.route('/health/detailed')
def detailed_health():
    """
    Detailed health check with timing information.

    Returns comprehensive health status including response times for each
    dependency. Useful for debugging and monitoring dashboards.
    """
    # Lazy import to avoid circular dependency
    from dashboard.mdt_collector import get_mdt_collector

    checks = {}

    # Redis check with timing
    start = time.time()
    redis_ok, redis_msg = check_redis_health()
    redis_time = (time.time() - start) * 1000
    checks["redis"] = {
        "healthy": redis_ok,
        "message": redis_msg,
        "response_time_ms": round(redis_time, 2)
    }

    # PostgreSQL check with timing
    start = time.time()
    postgres_ok, postgres_msg = check_postgres_health()
    postgres_time = (time.time() - start) * 1000
    checks["postgres"] = {
        "healthy": postgres_ok,
        "message": postgres_msg,
        "response_time_ms": round(postgres_time, 2)
    }

    # Celery check with timing
    start = time.time()
    celery_ok, celery_msg = check_celery_health()
    celery_time = (time.time() - start) * 1000
    checks["celery"] = {
        "healthy": celery_ok,
        "message": celery_msg,
        "response_time_ms": round(celery_time, 2)
    }

    # MDT collector
    mdt = get_mdt_collector()
    mdt_ok = mdt._running if mdt else False
    checks["mdt_collector"] = {
        "healthy": mdt_ok,
        "message": "running" if mdt_ok else "stopped",
        "response_time_ms": 0
    }

    # System info
    system_info = {
        "python_version": platform.python_version(),
        "platform": platform.system(),
        "hostname": platform.node(),
    }

    all_ok = all(c["healthy"] for c in checks.values())
    redis_critical = _REDIS_EXPLICITLY_CONFIGURED and not _DEMO_MODE
    critical_ok = checks["redis"]["healthy"] if redis_critical else True

    return jsonify({
        "status": "ok" if all_ok else ("degraded" if critical_ok else "unavailable"),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "service": "networkops-api",
        "version": os.getenv("APP_VERSION", "1.2.0"),
        "uptime_seconds": None,
        "checks": checks,
        "system": system_info,
    })


# =============================================================================
# Security Health
# =============================================================================

@health_bp.route('/api/health/security', methods=['GET'])
def security_health():
    """
    Security subsystem health status.

    OWASP compliance monitoring endpoint.
    Returns security feature status and Redis blacklist health.

    Public: Shows system_status and feature flags only.
    Admin (with JWT): Shows full Redis details (version, clients).
    """
    blacklist_status = get_redis_blacklist_status()

    # Determine overall system status
    system_status = "healthy"
    if not blacklist_status.get("available"):
        if os.getenv("REDIS_BLACKLIST_FAIL_CLOSED", "false").lower() == "true":
            system_status = "degraded"

    # Check if admin (for detailed info)
    is_admin = False
    auth_header = request.headers.get('Authorization')
    if auth_header and auth_header.startswith('Bearer '):
        try:
            payload = decode_token(auth_header.split(' ')[1])
            is_admin = payload and payload.get('role') == 'admin'
        except Exception:
            pass

    # Build response (sanitized for non-admins)
    response = {
        "system_status": system_status,
        "token_blacklist": {
            "available": blacklist_status.get("available"),
            "backend": blacklist_status.get("backend"),
        },
        "features": {
            "password_change_enforcement": ENFORCE_PASSWORD_CHANGE,
            "log_redaction": os.getenv("ENABLE_LOG_REDACTION", "true").lower() == "true",
            "redis_blacklist": os.getenv("USE_REDIS_BLACKLIST", "true").lower() == "true",
        },
        "timestamp": datetime.now(timezone.utc).isoformat()
    }

    # Add sensitive details for admins only
    if is_admin:
        response["token_blacklist"]["redis_version"] = blacklist_status.get("redis_version")
        response["token_blacklist"]["connected_clients"] = blacklist_status.get("connected_clients")
        if blacklist_status.get("warning"):
            response["token_blacklist"]["warning"] = blacklist_status.get("warning")

    return jsonify(response)


# =============================================================================
# Simple API Health (for backward compatibility)
# =============================================================================

@health_bp.route('/api/health')
def api_health():
    """Simple health check for API availability."""
    return jsonify({"status": "ok"})
