"""
Flask extension instances.

Centralized extension objects initialized via init_extensions(app).
Import these objects in blueprints instead of creating new instances.
"""

import os
import logging

from flask_socketio import SocketIO
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_caching import Cache

logger = logging.getLogger(__name__)

# Extension instances (uninitialized until init_extensions is called)
socketio = SocketIO()
limiter = None  # Created in init_extensions with full config
cache = Cache()


def _get_rate_limit_storage(redis_url):
    """Get rate limit storage URI, falling back to memory if Redis unavailable."""
    storage = os.getenv('RATE_LIMIT_STORAGE', redis_url)
    if storage and storage.startswith('redis://'):
        try:
            import redis
            r = redis.from_url(storage, socket_timeout=1)
            r.ping()
            return storage
        except Exception:
            logger.warning("Redis unavailable for rate limiting, using in-memory storage")
            return "memory://"
    return storage or "memory://"


def _get_rate_limit_key():
    """
    Custom rate limit key function.
    Uses authenticated username if available, otherwise IP address.
    """
    from dashboard.auth import get_token_from_request, decode_token
    token = get_token_from_request()
    if token:
        try:
            payload = decode_token(token)
            if payload:
                return f"user:{payload.get('sub', 'unknown')}"
        except Exception:
            pass
    return f"ip:{get_remote_address()}"


def _get_cache_config(redis_url):
    """Determine cache configuration, falling back to simple if Redis unavailable."""
    try:
        import redis
        redis_client = redis.from_url(redis_url)
        redis_client.ping()
        logger.info(f"Redis cache enabled: {redis_url}")
        return {
            'CACHE_TYPE': 'redis',
            'CACHE_REDIS_URL': redis_url,
            'CACHE_DEFAULT_TIMEOUT': 60,
        }
    except Exception as e:
        logger.warning(f"Redis unavailable, using simple cache: {e}")
        return {
            'CACHE_TYPE': 'simple',
            'CACHE_DEFAULT_TIMEOUT': 60,
        }


def init_extensions(app):
    """Initialize all Flask extensions with the app instance.

    Args:
        app: Flask application instance
    """
    redis_url = os.getenv('REDIS_URL', 'redis://localhost:6379/0')

    # CORS
    from flask_cors import CORS
    _default_origins = [
        "http://localhost:3000",
        "http://localhost:5001",
        "http://127.0.0.1:5001",
    ]
    _env_origins = os.getenv("CORS_ORIGINS", "")
    if _env_origins:
        allowed_origins = [o.strip() for o in _env_origins.split(",") if o.strip()]
    else:
        allowed_origins = _default_origins
    CORS(app, origins=allowed_origins)

    # Rate limiter — must be created with all config, then assigned to module-level
    global limiter
    rate_limit_storage = _get_rate_limit_storage(redis_url)
    rate_limit_default = os.getenv('RATE_LIMIT_DEFAULT', '500 per minute')

    limiter = Limiter(
        app=app,
        key_func=_get_rate_limit_key,
        default_limits=[rate_limit_default],
        storage_uri=rate_limit_storage,
        strategy="moving-window",
    )

    # Cache
    cache_config = _get_cache_config(redis_url)
    cache.init_app(app, config=cache_config)

    # SocketIO
    socketio.init_app(
        app,
        cors_allowed_origins=allowed_origins,
        async_mode=os.getenv("SOCKETIO_ASYNC_MODE", "threading"),
    )

    # Error handlers for rate limiting and general errors
    @app.errorhandler(429)
    def ratelimit_handler(e):
        from core import log_event
        log_event("rate_limit", "system", f"Rate limit exceeded: {e.description}", "warning")
        return {
            "error": "Rate limit exceeded",
            "message": str(e.description),
            "retry_after": e.get_response().headers.get("Retry-After", 60)
        }, 429
