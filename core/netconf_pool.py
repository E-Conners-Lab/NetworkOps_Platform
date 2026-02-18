"""
NETCONF Connection Pool.

Mirrors core/connection_pool.py pattern for synchronous ncclient connections.
Reuses SSH/NETCONF sessions to reduce connection overhead per operation.

Usage:
    from core.netconf_pool import pooled_netconf_connection

    with pooled_netconf_connection("R1") as m:
        response = m.get(filter=("subtree", filter_xml))

    # Pool statistics
    pool = get_netconf_pool()
    stats = pool.get_stats()
"""

import logging
import os
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Iterator, Optional

from ncclient import manager as ncclient_mgr
from ncclient.manager import Manager

from core.netconf_client import _get_netconf_params

logger = logging.getLogger(__name__)

# Pool configuration (overridable via env vars)
NETCONF_POOL_MAX_PER_DEVICE = int(os.getenv("NETCONF_POOL_MAX_PER_DEVICE", "2"))
NETCONF_POOL_MAX_IDLE_SECONDS = int(os.getenv("NETCONF_POOL_MAX_IDLE_SECONDS", "120"))
NETCONF_POOL_MAX_AGE_SECONDS = int(os.getenv("NETCONF_POOL_MAX_AGE_SECONDS", "300"))


@dataclass
class PooledNetconfConnection:
    """Wrapper for a pooled NETCONF connection with metadata."""
    manager: Manager
    device_name: str
    created_at: float = field(default_factory=time.time)
    last_used: float = field(default_factory=time.time)
    use_count: int = 0

    def touch(self):
        """Update last_used timestamp and increment use count."""
        self.last_used = time.time()
        self.use_count += 1

    @property
    def age_seconds(self) -> float:
        return time.time() - self.created_at

    @property
    def idle_seconds(self) -> float:
        return time.time() - self.last_used


class NetconfConnectionPool:
    """
    Synchronous NETCONF connection pool for ncclient.

    Thread-safe pool that reuses NETCONF sessions per device.
    """

    def __init__(
        self,
        max_per_device: int = NETCONF_POOL_MAX_PER_DEVICE,
        max_idle_seconds: int = NETCONF_POOL_MAX_IDLE_SECONDS,
        max_age_seconds: int = NETCONF_POOL_MAX_AGE_SECONDS,
    ):
        self.max_per_device = max_per_device
        self.max_idle_seconds = max_idle_seconds
        self.max_age_seconds = max_age_seconds

        # Pool storage: device_name -> list of available PooledNetconfConnections
        self._pools: dict[str, list[PooledNetconfConnection]] = {}
        self._in_use: dict[str, set[int]] = {}  # track by id

        self._lock = threading.Lock()

        self._stats = {
            "hits": 0,
            "misses": 0,
            "evictions": 0,
            "active": 0,
        }

        logger.info(
            f"NetconfConnectionPool initialized: max_per_device={max_per_device}, "
            f"max_idle={max_idle_seconds}s, max_age={max_age_seconds}s"
        )

    def acquire(self, device_name: str, timeout: Optional[int] = None) -> Manager:
        """
        Acquire a NETCONF connection from the pool.

        Returns an existing valid connection or creates a new one.
        """
        with self._lock:
            if device_name not in self._pools:
                self._pools[device_name] = []
                self._in_use[device_name] = set()

            pool = self._pools[device_name]

            # Try to reuse an existing connection
            while pool:
                pooled = pool.pop(0)
                if self._is_valid(pooled):
                    pooled.touch()
                    self._in_use[device_name].add(id(pooled))
                    self._stats["hits"] += 1
                    self._stats["active"] += 1
                    logger.debug(
                        f"Pool hit for {device_name} (use_count={pooled.use_count})"
                    )
                    # Store the wrapper so release can find it
                    if not hasattr(self, '_wrappers'):
                        self._wrappers: dict[int, PooledNetconfConnection] = {}
                    self._wrappers[id(pooled)] = pooled
                    return pooled.manager
                else:
                    self._evict(pooled)

            # Create new connection
            self._stats["misses"] += 1

        # Create outside lock (connection is slow)
        params = _get_netconf_params(device_name)
        if timeout is not None:
            params["timeout"] = timeout

        logger.info(f"Pool miss for {device_name}, creating new NETCONF connection")
        mgr = ncclient_mgr.connect(**params)

        pooled = PooledNetconfConnection(manager=mgr, device_name=device_name)
        pooled.touch()

        with self._lock:
            self._in_use.setdefault(device_name, set()).add(id(pooled))
            self._stats["active"] += 1
            if not hasattr(self, '_wrappers'):
                self._wrappers = {}
            self._wrappers[id(pooled)] = pooled

        return mgr

    def release(self, device_name: str, mgr: Manager):
        """Return a connection to the pool."""
        with self._lock:
            # Find the wrapper for this manager
            pooled = None
            if hasattr(self, '_wrappers'):
                for wrapper_id, wrapper in list(self._wrappers.items()):
                    if wrapper.manager is mgr:
                        pooled = wrapper
                        del self._wrappers[wrapper_id]
                        break

            if pooled is None:
                logger.warning(f"Release called for untracked NETCONF connection: {device_name}")
                try:
                    mgr.close_session()
                except Exception:
                    pass
                return

            in_use = self._in_use.get(device_name, set())
            in_use.discard(id(pooled))
            self._stats["active"] = max(0, self._stats["active"] - 1)

            if self._is_valid(pooled):
                self._pools.setdefault(device_name, []).append(pooled)
                logger.debug(f"Connection returned to pool for {device_name}")
            else:
                self._evict(pooled)

    def _is_valid(self, pooled: PooledNetconfConnection) -> bool:
        """Check if a connection is still valid for reuse."""
        # Check if ncclient session is still connected
        try:
            if not pooled.manager.connected:
                logger.debug(f"Connection disconnected for {pooled.device_name}")
                return False
        except Exception:
            return False

        if pooled.idle_seconds > self.max_idle_seconds:
            logger.debug(
                f"Connection idle too long for {pooled.device_name}: "
                f"{pooled.idle_seconds:.0f}s > {self.max_idle_seconds}s"
            )
            return False

        if pooled.age_seconds > self.max_age_seconds:
            logger.debug(
                f"Connection too old for {pooled.device_name}: "
                f"{pooled.age_seconds:.0f}s > {self.max_age_seconds}s"
            )
            return False

        return True

    def _evict(self, pooled: PooledNetconfConnection):
        """Close and discard an invalid connection."""
        self._stats["evictions"] += 1
        try:
            pooled.manager.close_session()
        except Exception:
            pass
        logger.debug(
            f"Evicted NETCONF connection for {pooled.device_name} "
            f"(age={pooled.age_seconds:.0f}s, uses={pooled.use_count})"
        )

    def cleanup_idle(self) -> int:
        """Close all idle connections that have expired."""
        with self._lock:
            closed = 0
            for device_name, pool in self._pools.items():
                valid = []
                for pooled in pool:
                    if self._is_valid(pooled):
                        valid.append(pooled)
                    else:
                        self._evict(pooled)
                        closed += 1
                self._pools[device_name] = valid
            if closed > 0:
                logger.info(f"NETCONF pool cleanup: evicted {closed} connections")
            return closed

    def close_all(self):
        """Close all connections in the pool."""
        with self._lock:
            total = 0
            for device_name, pool in self._pools.items():
                for pooled in pool:
                    try:
                        pooled.manager.close_session()
                    except Exception:
                        pass
                    total += 1
                pool.clear()

            # Also close wrappers dict
            if hasattr(self, '_wrappers'):
                self._wrappers.clear()

            self._in_use.clear()
            self._stats["active"] = 0
            logger.info(f"Closed all {total} NETCONF connections")

    def get_stats(self) -> dict:
        """Get pool statistics (Prometheus-compatible keys)."""
        with self._lock:
            pool_sizes = {name: len(pool) for name, pool in self._pools.items()}
            return {
                "netconf_pool_hits_total": self._stats["hits"],
                "netconf_pool_misses_total": self._stats["misses"],
                "netconf_pool_evictions_total": self._stats["evictions"],
                "netconf_pool_active_connections": self._stats["active"],
                "pool_sizes": pool_sizes,
                "total_pooled": sum(pool_sizes.values()),
            }


# Global singleton
_netconf_pool: Optional[NetconfConnectionPool] = None


def get_netconf_pool() -> NetconfConnectionPool:
    """Get the global NETCONF connection pool instance."""
    global _netconf_pool
    if _netconf_pool is None:
        _netconf_pool = NetconfConnectionPool()
    return _netconf_pool


@contextmanager
def pooled_netconf_connection(
    device_name: str,
    timeout: Optional[int] = None,
) -> Iterator[Manager]:
    """
    Context manager for pooled NETCONF connections.

    Usage:
        with pooled_netconf_connection("R1") as m:
            response = m.get(filter=("subtree", filter_xml))
    """
    pool = get_netconf_pool()
    mgr = pool.acquire(device_name, timeout)
    try:
        yield mgr
    finally:
        pool.release(device_name, mgr)
