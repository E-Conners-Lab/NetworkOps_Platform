"""
Graceful shutdown and lifecycle management.

Extracted from api_server.py lines 251-317.
"""

import os
import time
import signal
import logging
import atexit

logger = logging.getLogger(__name__)

_shutdown_in_progress = False
_active_requests = 0


def increment_active_requests():
    """Increment active request counter."""
    global _active_requests
    _active_requests += 1


def decrement_active_requests():
    """Decrement active request counter."""
    global _active_requests
    _active_requests = max(0, _active_requests - 1)


def get_active_requests():
    """Return current active request count."""
    return _active_requests


def graceful_shutdown(signum, frame):
    """Handle graceful shutdown on SIGTERM/SIGINT."""
    global _shutdown_in_progress

    if _shutdown_in_progress:
        logger.warning("Forced shutdown requested")
        raise SystemExit(1)

    _shutdown_in_progress = True
    signal_name = signal.Signals(signum).name
    logger.info(f"Received {signal_name}, starting graceful shutdown...")

    # Stop MDT collector
    logger.info("Stopping MDT collector...")
    try:
        from dashboard.mdt_collector import get_mdt_collector
        mdt = get_mdt_collector()
        if mdt and mdt._running:
            mdt.stop()
    except Exception as e:
        logger.warning(f"Error stopping MDT collector: {e}")

    # Wait for active requests to complete
    shutdown_timeout = int(os.getenv('SHUTDOWN_TIMEOUT', '30'))
    start_time = time.time()

    while _active_requests > 0 and (time.time() - start_time) < shutdown_timeout:
        logger.info(f"Waiting for {_active_requests} active requests to complete...")
        time.sleep(1)

    if _active_requests > 0:
        logger.warning(f"Shutdown timeout reached with {_active_requests} requests still active")
    else:
        logger.info("All requests completed")

    # Close database connections
    logger.info("Closing database connections...")
    try:
        from core.models import engine
        engine.dispose()
    except Exception as e:
        logger.debug(f"Database cleanup: {e}")

    # Close Redis connections
    logger.info("Closing Redis connections...")
    try:
        from config.redis_client import close_redis
        close_redis()
    except Exception as e:
        logger.debug(f"Redis cleanup: {e}")

    logger.info("Graceful shutdown complete")
    raise SystemExit(0)


def register_shutdown_handlers():
    """Register signal handlers for graceful shutdown."""
    signal.signal(signal.SIGTERM, graceful_shutdown)
    signal.signal(signal.SIGINT, graceful_shutdown)
    logger.info("Registered shutdown handlers for SIGTERM and SIGINT")


@atexit.register
def cleanup_on_exit():
    """Cleanup resources on normal exit."""
    logger.info("Application exiting, cleaning up resources...")
