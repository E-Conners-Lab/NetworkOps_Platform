"""
Redis pub/sub to WebSocket bridge for MDT telemetry.

When MDT_EXTERNAL=true, the MDT collector runs as a separate process
and publishes updates via Redis. This bridge subscribes to those updates
and forwards them to WebSocket clients.

Includes exponential backoff with jitter for Redis reconnection.
"""

import json
import logging
import random
import threading
import time

logger = logging.getLogger(__name__)

# Reconnection parameters
_RECONNECT_BASE = 1.0  # 1 second
_RECONNECT_MAX = 30.0  # 30 seconds
_RECONNECT_JITTER = 0.25  # ±25%

# Redis pub/sub channel
MDT_CHANNEL = "mdt:updates"


def _backoff_with_jitter(attempt: int) -> float:
    """Calculate exponential backoff with jitter."""
    delay = min(_RECONNECT_BASE * (2 ** attempt), _RECONNECT_MAX)
    jitter = delay * _RECONNECT_JITTER * (2 * random.random() - 1)
    return delay + jitter


def start_telemetry_ws_bridge(socketio_instance):
    """
    Start a background thread that bridges Redis pub/sub to WebSocket.

    Subscribes to the "mdt:updates" Redis channel and emits
    socketio events matching the current callback format.

    Args:
        socketio_instance: Flask-SocketIO instance
    """
    def bridge_loop():
        attempt = 0

        while True:
            try:
                import redis
                from config.settings import get_settings

                settings = get_settings()
                r = redis.from_url(settings.redis.redis_url)
                pubsub = r.pubsub()
                pubsub.subscribe(MDT_CHANNEL)

                logger.info(f"Telemetry WS bridge connected to Redis ({MDT_CHANNEL})")
                attempt = 0  # Reset on successful connection

                for message in pubsub.listen():
                    if message["type"] != "message":
                        continue

                    try:
                        data = json.loads(message["data"])
                        event_type = data.get("event", "telemetry_update")
                        payload = data.get("payload", data)

                        socketio_instance.emit(event_type, payload)

                    except (json.JSONDecodeError, KeyError) as e:
                        logger.warning(f"Invalid telemetry message: {e}")

            except ImportError:
                logger.error("redis package required for telemetry bridge")
                return

            except Exception as e:
                delay = _backoff_with_jitter(attempt)
                logger.warning(
                    f"Telemetry bridge disconnected: {e}. "
                    f"Reconnecting in {delay:.1f}s (attempt {attempt + 1})"
                )
                time.sleep(delay)
                attempt += 1

    thread = threading.Thread(
        target=bridge_loop,
        daemon=True,
        name="TelemetryWSBridge",
    )
    thread.start()
    logger.info("Telemetry WebSocket bridge started")
    return thread
