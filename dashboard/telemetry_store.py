"""
Redis-backed Telemetry Data Store.

Enables sharing telemetry data between the standalone MDT collector
and the dashboard API server (separate processes).

Falls back to in-memory storage when Redis is unavailable.
"""

import json
import logging
import os
from core.timestamps import isonow
from typing import Optional

logger = logging.getLogger(__name__)

# Redis configuration
REDIS_URL = os.getenv('REDIS_URL', 'redis://localhost:6379/0')
TELEMETRY_TTL = int(os.getenv('TELEMETRY_TTL', '300'))  # 5 minutes default

# Redis key prefixes
KEY_PREFIX = 'mdt:'
CPU_KEY = f'{KEY_PREFIX}cpu'
MEMORY_KEY = f'{KEY_PREFIX}memory'
INTERFACES_KEY = f'{KEY_PREFIX}interfaces'
INTERFACE_STATES_KEY = f'{KEY_PREFIX}interface_states'
STATE_HISTORY_KEY = f'{KEY_PREFIX}state_history'
LAST_UPDATE_KEY = f'{KEY_PREFIX}last_update'
COLLECTOR_STATUS_KEY = f'{KEY_PREFIX}collector_status'


MDT_PUBSUB_CHANNEL = "mdt:updates"


class RedisTelemetryStore:
    """
    Redis-backed telemetry data store.

    Data is stored in Redis hashes for efficient per-device access:
    - mdt:cpu -> {device: json_data}
    - mdt:memory -> {device: json_data}
    - mdt:interfaces:{device} -> {interface: json_data}
    - mdt:interface_states:{device} -> {interface: json_data}
    - mdt:state_history -> list of json events (capped at 100)
    - mdt:last_update -> {device: timestamp}
    - mdt:collector_status -> {running, port, message_count, connected_devices}

    When Redis is available, publishes updates to the 'mdt:updates' channel
    for cross-process consumption (MDT_EXTERNAL mode).
    """

    def __init__(self):
        self._redis = None
        self._fallback_data = {
            'cpu': {},
            'memory': {},
            'interfaces': {},
            'interface_states': {},
            'state_history': [],
            'last_update': {},
        }
        self._connect()

    def _connect(self):
        """Connect to Redis."""
        try:
            import redis
            self._redis = redis.from_url(REDIS_URL, decode_responses=True)
            self._redis.ping()
            logger.info(f"Connected to Redis for telemetry store: {REDIS_URL}")
        except Exception as e:
            logger.warning(f"Redis unavailable for telemetry, using in-memory: {e}")
            self._redis = None

    def _publish(self, event: str, payload: dict):
        """Publish update to Redis pub/sub for cross-process bridge."""
        if self._redis is not None:
            try:
                self._redis.publish(
                    MDT_PUBSUB_CHANNEL,
                    json.dumps({"event": event, "payload": payload})
                )
            except Exception:
                pass  # Pub/sub failure should not block data storage

    @property
    def is_redis_available(self) -> bool:
        """Check if Redis is available."""
        if self._redis is None:
            return False
        try:
            self._redis.ping()
            return True
        except Exception:
            self._redis = None
            return False

    # =========================================================================
    # CPU Stats
    # =========================================================================
    def update_cpu_stats(self, device: str, cpu_percent: float):
        """Update CPU stats for a device."""
        data = {
            'five_seconds': cpu_percent,
            'timestamp': isonow()
        }

        if self.is_redis_available:
            self._redis.hset(CPU_KEY, device, json.dumps(data))
            self._redis.expire(CPU_KEY, TELEMETRY_TTL)
            self._update_last_update(device)
            self._publish("telemetry_update", {"device": device, "type": "cpu", "data": data})
        else:
            self._fallback_data['cpu'][device] = data
            self._fallback_data['last_update'][device] = data['timestamp']

    def get_cpu_stats(self) -> dict:
        """Get CPU stats for all devices."""
        if self.is_redis_available:
            raw = self._redis.hgetall(CPU_KEY)
            return {k: json.loads(v) for k, v in raw.items()}
        return dict(self._fallback_data['cpu'])

    # =========================================================================
    # Memory Stats
    # =========================================================================
    def update_memory_stats(self, device: str, used: int, free: int):
        """Update memory stats for a device."""
        used = max(0, used)
        free = max(0, free)
        total = used + free

        if total <= 0:
            return

        data = {
            'used': used,
            'free': free,
            'total': total,
            'percent_used': round((used / total) * 100, 1),
            'timestamp': isonow()
        }

        if self.is_redis_available:
            self._redis.hset(MEMORY_KEY, device, json.dumps(data))
            self._redis.expire(MEMORY_KEY, TELEMETRY_TTL)
            self._update_last_update(device)
            self._publish("telemetry_update", {"device": device, "type": "memory", "data": data})
        else:
            self._fallback_data['memory'][device] = data
            self._fallback_data['last_update'][device] = data['timestamp']

    def get_memory_stats(self) -> dict:
        """Get memory stats for all devices."""
        if self.is_redis_available:
            raw = self._redis.hgetall(MEMORY_KEY)
            return {k: json.loads(v) for k, v in raw.items()}
        return dict(self._fallback_data['memory'])

    # =========================================================================
    # Interface Stats
    # =========================================================================
    def update_interface_stats(self, device: str, interface: str, stats: dict):
        """Update interface stats for a device."""
        data = {
            **stats,
            'timestamp': isonow()
        }

        if self.is_redis_available:
            key = f'{INTERFACES_KEY}:{device}'
            self._redis.hset(key, interface, json.dumps(data))
            self._redis.expire(key, TELEMETRY_TTL)
            self._update_last_update(device)
            self._publish("telemetry_update", {"device": device, "type": "interface", "interface": interface, "data": data})
        else:
            if device not in self._fallback_data['interfaces']:
                self._fallback_data['interfaces'][device] = {}
            self._fallback_data['interfaces'][device][interface] = data
            self._fallback_data['last_update'][device] = data['timestamp']

    def get_interface_stats(self) -> dict:
        """Get interface stats for all devices."""
        if self.is_redis_available:
            result = {}
            # Scan for all interface keys
            for key in self._redis.scan_iter(f'{INTERFACES_KEY}:*'):
                device = key.split(':')[-1]
                raw = self._redis.hgetall(key)
                result[device] = {k: json.loads(v) for k, v in raw.items()}
            return result
        return dict(self._fallback_data['interfaces'])

    # =========================================================================
    # Interface States (for on-change subscriptions)
    # =========================================================================
    def update_interface_state(self, device: str, interface: str, new_state: str) -> Optional[dict]:
        """
        Update interface state and detect changes.
        Returns state change event if state changed, None otherwise.
        """
        timestamp = isonow()
        state_up = 'ready' in new_state.lower() or new_state.lower() == 'up'
        simple_state = 'up' if state_up else 'down'

        data = {
            'state': simple_state,
            'raw_state': new_state,
            'timestamp': timestamp
        }

        # Get previous state
        prev_state = None
        if self.is_redis_available:
            key = f'{INTERFACE_STATES_KEY}:{device}'
            prev_raw = self._redis.hget(key, interface)
            if prev_raw:
                prev_state = json.loads(prev_raw).get('state')

            self._redis.hset(key, interface, json.dumps(data))
            self._redis.expire(key, TELEMETRY_TTL)
            self._update_last_update(device)
        else:
            if device in self._fallback_data['interface_states']:
                prev_data = self._fallback_data['interface_states'][device].get(interface, {})
                prev_state = prev_data.get('state')

            if device not in self._fallback_data['interface_states']:
                self._fallback_data['interface_states'][device] = {}
            self._fallback_data['interface_states'][device][interface] = data
            self._fallback_data['last_update'][device] = timestamp

        # Check for state change
        if prev_state is not None and prev_state != simple_state:
            event = {
                'device': device,
                'interface': interface,
                'old_state': prev_state,
                'new_state': simple_state,
                'raw_state': new_state,
                'timestamp': timestamp
            }
            self._add_state_change(event)
            return event

        return None

    def get_interface_states(self) -> dict:
        """Get interface states for all devices."""
        if self.is_redis_available:
            result = {}
            for key in self._redis.scan_iter(f'{INTERFACE_STATES_KEY}:*'):
                device = key.split(':')[-1]
                raw = self._redis.hgetall(key)
                result[device] = {k: json.loads(v) for k, v in raw.items()}
            return result
        return {d: dict(s) for d, s in self._fallback_data['interface_states'].items()}

    # =========================================================================
    # State Change History
    # =========================================================================
    def _add_state_change(self, event: dict):
        """Add a state change event to history."""
        if self.is_redis_available:
            self._redis.rpush(STATE_HISTORY_KEY, json.dumps(event))
            self._redis.ltrim(STATE_HISTORY_KEY, -100, -1)  # Keep last 100
            self._redis.expire(STATE_HISTORY_KEY, TELEMETRY_TTL * 2)
        else:
            self._fallback_data['state_history'].append(event)
            if len(self._fallback_data['state_history']) > 100:
                self._fallback_data['state_history'].pop(0)

    def get_state_change_history(self, limit: int = 50) -> list:
        """Get recent state change events."""
        if self.is_redis_available:
            raw = self._redis.lrange(STATE_HISTORY_KEY, -limit, -1)
            return [json.loads(x) for x in raw]
        return list(self._fallback_data['state_history'][-limit:])

    # =========================================================================
    # Last Update Timestamps
    # =========================================================================
    def _update_last_update(self, device: str):
        """Update last update timestamp for a device."""
        if self.is_redis_available:
            self._redis.hset(LAST_UPDATE_KEY, device, isonow())
            self._redis.expire(LAST_UPDATE_KEY, TELEMETRY_TTL)

    def get_last_updates(self) -> dict:
        """Get last update timestamps for all devices."""
        if self.is_redis_available:
            return self._redis.hgetall(LAST_UPDATE_KEY)
        return dict(self._fallback_data['last_update'])

    # =========================================================================
    # Collector Status (shared between processes)
    # =========================================================================
    def set_collector_status(self, running: bool, port: int, message_count: int,
                            connected_devices: list):
        """Update collector status in Redis."""
        data = {
            'running': running,
            'port': port,
            'message_count': message_count,
            'connected_devices': connected_devices,
            'timestamp': isonow()
        }

        if self.is_redis_available:
            self._redis.set(COLLECTOR_STATUS_KEY, json.dumps(data))
            self._redis.expire(COLLECTOR_STATUS_KEY, 30)  # Short TTL - collector updates frequently

    def get_collector_status(self) -> Optional[dict]:
        """Get collector status from Redis."""
        if self.is_redis_available:
            raw = self._redis.get(COLLECTOR_STATUS_KEY)
            if raw:
                return json.loads(raw)
        return None

    # =========================================================================
    # Aggregated Data Access
    # =========================================================================
    def get_all_stats(self) -> dict:
        """Get all telemetry data."""
        return {
            'interfaces': self.get_interface_stats(),
            'cpu': self.get_cpu_stats(),
            'memory': self.get_memory_stats(),
            'interface_states': self.get_interface_states(),
            'state_changes': self.get_state_change_history(10),
            'last_update': self.get_last_updates()
        }

    def get_device_stats(self, device: str) -> dict:
        """Get telemetry data for a specific device."""
        all_stats = self.get_all_stats()
        return {
            'interfaces': all_stats['interfaces'].get(device, {}),
            'cpu': all_stats['cpu'].get(device),
            'memory': all_stats['memory'].get(device),
            'interface_states': all_stats['interface_states'].get(device, {}),
            'last_update': all_stats['last_update'].get(device)
        }


# Module-level singleton
_store: Optional[RedisTelemetryStore] = None


def get_telemetry_store() -> RedisTelemetryStore:
    """Get or create the telemetry store singleton."""
    global _store
    if _store is None:
        _store = RedisTelemetryStore()
    return _store
