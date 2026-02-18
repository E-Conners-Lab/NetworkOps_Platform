"""
Redis client configuration for caching and state management.

Usage:
    from config.redis_client import get_redis, redis_available

    if redis_available():
        redis = get_redis()
        redis.set("key", "value", ex=60)  # 60 second TTL
"""

import os
import logging
from typing import Optional

logger = logging.getLogger(__name__)

# Redis connection URL - defaults to localhost for development
REDIS_URL = os.getenv('REDIS_URL', 'redis://localhost:6379/0')

# Global Redis client instance
_redis_client = None
_redis_available = None


def get_redis():
    """
    Get the Redis client instance.

    Returns:
        redis.Redis: Connected Redis client

    Raises:
        ConnectionError: If Redis is not available
    """
    global _redis_client

    if _redis_client is None:
        import redis
        _redis_client = redis.from_url(REDIS_URL, decode_responses=True)

    return _redis_client


def redis_available() -> bool:
    """
    Check if Redis is available and responding.

    Returns:
        bool: True if Redis is reachable, False otherwise
    """
    global _redis_available

    # Cache the result to avoid repeated connection attempts
    if _redis_available is not None:
        return _redis_available

    try:
        client = get_redis()
        client.ping()
        _redis_available = True
        logger.info(f"Redis connected: {REDIS_URL}")
    except Exception as e:
        _redis_available = False
        logger.warning(f"Redis not available ({REDIS_URL}): {e}")

    return _redis_available


def reset_redis_connection():
    """Reset the Redis connection (useful for testing or reconnection)."""
    global _redis_client, _redis_available
    _redis_client = None
    _redis_available = None


# Cache key prefixes for organization
class CacheKeys:
    """Standard cache key prefixes."""

    # Device state (TTL: 30s)
    DEVICE_HEALTH = "device:{device}:health"

    # Interface data (TTL: 60s)
    DEVICE_INTERFACES = "device:{device}:interfaces"

    # Topology (TTL: 120s)
    TOPOLOGY = "topology:full"
    TOPOLOGY_NODES = "topology:nodes"
    TOPOLOGY_LINKS = "topology:links"

    # BGP/DMVPN state (TTL: 45s)
    BGP_SUMMARY = "bgp:{device}:summary"
    DMVPN_STATUS = "dmvpn:status"

    # Switch status (TTL: 45s)
    SWITCH_STATUS = "switch:status"

    @classmethod
    def device_health(cls, device: str) -> str:
        return cls.DEVICE_HEALTH.format(device=device)

    @classmethod
    def device_interfaces(cls, device: str) -> str:
        return cls.DEVICE_INTERFACES.format(device=device)

    @classmethod
    def bgp_summary(cls, device: str) -> str:
        return cls.BGP_SUMMARY.format(device=device)


# Default TTLs in seconds
class CacheTTL:
    """Default TTL values for different cache types."""

    DEVICE_HEALTH = 30
    DEVICE_INTERFACES = 60
    TOPOLOGY = 120
    BGP_DMVPN = 45
    SWITCH_STATUS = 45
    DEVICES_LIST = 300
    INTERFACE_STATS = 20
