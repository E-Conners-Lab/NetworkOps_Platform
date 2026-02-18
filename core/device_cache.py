"""
Device state caching layer using Redis.

Provides caching for device health, interface status, and topology data
to reduce SSH connections and improve response times.

Usage:
    from core.device_cache import DeviceCache

    cache = DeviceCache()

    # Check cache before expensive operation
    health = await cache.get_health("R1")
    if health is None:
        health = await fetch_health_from_device("R1")
        await cache.set_health("R1", health)
"""

import json
import logging
from typing import Optional, Any
from core.timestamps import isonow

from config.redis_client import (
    get_redis,
    redis_available,
    CacheKeys,
    CacheTTL
)

logger = logging.getLogger(__name__)


class DeviceCache:
    """
    Redis-backed cache for device state data.

    Falls back to no-caching when Redis is unavailable.
    """

    def __init__(self):
        self._enabled = redis_available()
        if self._enabled:
            self._redis = get_redis()
            logger.info("DeviceCache initialized with Redis backend")
        else:
            self._redis = None
            logger.warning("DeviceCache running without Redis (no caching)")

    @property
    def enabled(self) -> bool:
        """Check if caching is enabled."""
        return self._enabled

    # =========================================================================
    # Device Health Caching
    # =========================================================================

    async def get_health(self, device_name: str) -> Optional[dict]:
        """
        Get cached health data for a device.

        Args:
            device_name: Name of the device (e.g., "R1")

        Returns:
            Cached health dict or None if not cached/expired
        """
        if not self._enabled:
            return None

        key = CacheKeys.device_health(device_name)
        try:
            data = self._redis.get(key)
            if data:
                logger.debug(f"Cache HIT: {key}")
                return json.loads(data)
            logger.debug(f"Cache MISS: {key}")
        except Exception as e:
            logger.warning(f"Cache read error for {key}: {e}")
        return None

    async def set_health(
        self,
        device_name: str,
        health_data: dict,
        ttl: int = CacheTTL.DEVICE_HEALTH
    ) -> bool:
        """
        Cache health data for a device.

        Args:
            device_name: Name of the device
            health_data: Health check result dict
            ttl: Time-to-live in seconds (default: 30s)

        Returns:
            True if cached successfully, False otherwise
        """
        if not self._enabled:
            return False

        key = CacheKeys.device_health(device_name)
        try:
            # Add cache timestamp
            health_data['_cached_at'] = isonow()
            self._redis.set(key, json.dumps(health_data), ex=ttl)
            logger.debug(f"Cache SET: {key} (TTL: {ttl}s)")
            return True
        except Exception as e:
            logger.warning(f"Cache write error for {key}: {e}")
        return False

    async def get_health_batch(self, device_names: list[str]) -> dict[str, Optional[dict]]:
        """
        Get cached health for multiple devices in one operation.

        Args:
            device_names: List of device names

        Returns:
            Dict mapping device_name -> health_data (or None if not cached)
        """
        if not self._enabled:
            return {name: None for name in device_names}

        results = {}
        try:
            keys = [CacheKeys.device_health(name) for name in device_names]
            values = self._redis.mget(keys)

            for name, value in zip(device_names, values):
                if value:
                    results[name] = json.loads(value)
                    logger.debug(f"Cache HIT: device:{name}:health")
                else:
                    results[name] = None
                    logger.debug(f"Cache MISS: device:{name}:health")
        except Exception as e:
            logger.warning(f"Batch cache read error: {e}")
            results = {name: None for name in device_names}

        return results

    # =========================================================================
    # Interface Data Caching
    # =========================================================================

    async def get_interfaces(self, device_name: str) -> Optional[dict]:
        """Get cached interface data for a device."""
        if not self._enabled:
            return None

        key = CacheKeys.device_interfaces(device_name)
        try:
            data = self._redis.get(key)
            if data:
                return json.loads(data)
        except Exception as e:
            logger.warning(f"Cache read error for {key}: {e}")
        return None

    async def set_interfaces(
        self,
        device_name: str,
        interface_data: dict,
        ttl: int = CacheTTL.DEVICE_INTERFACES
    ) -> bool:
        """Cache interface data for a device."""
        if not self._enabled:
            return False

        key = CacheKeys.device_interfaces(device_name)
        try:
            interface_data['_cached_at'] = isonow()
            self._redis.set(key, json.dumps(interface_data), ex=ttl)
            return True
        except Exception as e:
            logger.warning(f"Cache write error for {key}: {e}")
        return False

    # =========================================================================
    # Topology Caching
    # =========================================================================

    async def get_topology(self) -> Optional[dict]:
        """Get cached full topology data."""
        if not self._enabled:
            return None

        try:
            data = self._redis.get(CacheKeys.TOPOLOGY)
            if data:
                logger.debug("Cache HIT: topology:full")
                return json.loads(data)
            logger.debug("Cache MISS: topology:full")
        except Exception as e:
            logger.warning(f"Topology cache read error: {e}")
        return None

    async def set_topology(
        self,
        topology_data: dict,
        ttl: int = CacheTTL.TOPOLOGY
    ) -> bool:
        """Cache full topology data."""
        if not self._enabled:
            return False

        try:
            topology_data['_cached_at'] = isonow()
            self._redis.set(CacheKeys.TOPOLOGY, json.dumps(topology_data), ex=ttl)
            logger.debug(f"Cache SET: topology:full (TTL: {ttl}s)")
            return True
        except Exception as e:
            logger.warning(f"Topology cache write error: {e}")
        return False

    # =========================================================================
    # BGP/DMVPN Caching
    # =========================================================================

    async def get_bgp_summary(self, device_name: str) -> Optional[dict]:
        """Get cached BGP summary for a device."""
        if not self._enabled:
            return None

        key = CacheKeys.bgp_summary(device_name)
        try:
            data = self._redis.get(key)
            if data:
                return json.loads(data)
        except Exception as e:
            logger.warning(f"Cache read error for {key}: {e}")
        return None

    async def set_bgp_summary(
        self,
        device_name: str,
        bgp_data: dict,
        ttl: int = CacheTTL.BGP_DMVPN
    ) -> bool:
        """Cache BGP summary for a device."""
        if not self._enabled:
            return False

        key = CacheKeys.bgp_summary(device_name)
        try:
            bgp_data['_cached_at'] = isonow()
            self._redis.set(key, json.dumps(bgp_data), ex=ttl)
            return True
        except Exception as e:
            logger.warning(f"Cache write error for {key}: {e}")
        return False

    async def get_dmvpn_status(self) -> Optional[dict]:
        """Get cached DMVPN status."""
        if not self._enabled:
            return None

        try:
            data = self._redis.get(CacheKeys.DMVPN_STATUS)
            if data:
                return json.loads(data)
        except Exception as e:
            logger.warning(f"DMVPN cache read error: {e}")
        return None

    async def set_dmvpn_status(
        self,
        dmvpn_data: dict,
        ttl: int = CacheTTL.BGP_DMVPN
    ) -> bool:
        """Cache DMVPN status."""
        if not self._enabled:
            return False

        try:
            dmvpn_data['_cached_at'] = isonow()
            self._redis.set(CacheKeys.DMVPN_STATUS, json.dumps(dmvpn_data), ex=ttl)
            return True
        except Exception as e:
            logger.warning(f"DMVPN cache write error: {e}")
        return False

    # =========================================================================
    # Cache Invalidation
    # =========================================================================

    async def invalidate_device(self, device_name: str) -> int:
        """
        Invalidate all cached data for a specific device.

        Args:
            device_name: Device to invalidate

        Returns:
            Number of keys deleted
        """
        if not self._enabled:
            return 0

        try:
            pattern = f"device:{device_name}:*"
            keys = list(self._redis.scan_iter(match=pattern))
            if keys:
                deleted = self._redis.delete(*keys)
                logger.info(f"Invalidated {deleted} cache keys for {device_name}")
                return deleted
        except Exception as e:
            logger.warning(f"Cache invalidation error for {device_name}: {e}")
        return 0

    async def invalidate_topology(self) -> bool:
        """Invalidate topology cache."""
        if not self._enabled:
            return False

        try:
            self._redis.delete(CacheKeys.TOPOLOGY)
            self._redis.delete(CacheKeys.TOPOLOGY_NODES)
            self._redis.delete(CacheKeys.TOPOLOGY_LINKS)
            logger.info("Invalidated topology cache")
            return True
        except Exception as e:
            logger.warning(f"Topology invalidation error: {e}")
        return False

    async def invalidate_all(self) -> int:
        """
        Invalidate ALL cached data.

        Use with caution - clears entire cache.

        Returns:
            Number of keys deleted
        """
        if not self._enabled:
            return 0

        try:
            # Only delete our keys, not all Redis data
            patterns = ["device:*", "topology:*", "bgp:*", "dmvpn:*", "switch:*"]
            total_deleted = 0

            for pattern in patterns:
                keys = list(self._redis.scan_iter(match=pattern))
                if keys:
                    total_deleted += self._redis.delete(*keys)

            logger.info(f"Invalidated {total_deleted} total cache keys")
            return total_deleted
        except Exception as e:
            logger.warning(f"Full cache invalidation error: {e}")
        return 0

    # =========================================================================
    # Cache Statistics
    # =========================================================================

    def get_stats(self) -> dict:
        """
        Get cache statistics.

        Returns:
            Dict with cache stats (key counts, memory usage, etc.)
        """
        if not self._enabled:
            return {"enabled": False, "reason": "Redis not available"}

        try:
            info = self._redis.info()

            # Count our keys by type
            key_counts = {
                "device_health": len(list(self._redis.scan_iter(match="device:*:health"))),
                "device_interfaces": len(list(self._redis.scan_iter(match="device:*:interfaces"))),
                "topology": 1 if self._redis.exists(CacheKeys.TOPOLOGY) else 0,
                "bgp": len(list(self._redis.scan_iter(match="bgp:*"))),
                "dmvpn": 1 if self._redis.exists(CacheKeys.DMVPN_STATUS) else 0,
            }

            return {
                "enabled": True,
                "connected": True,
                "redis_version": info.get("redis_version"),
                "used_memory_human": info.get("used_memory_human"),
                "connected_clients": info.get("connected_clients"),
                "key_counts": key_counts,
                "total_keys": sum(key_counts.values()),
            }
        except Exception as e:
            return {"enabled": True, "connected": False, "error": str(e)}


# Global cache instance
_device_cache: Optional[DeviceCache] = None


def get_device_cache() -> DeviceCache:
    """Get the global DeviceCache instance."""
    global _device_cache
    if _device_cache is None:
        _device_cache = DeviceCache()
    return _device_cache
