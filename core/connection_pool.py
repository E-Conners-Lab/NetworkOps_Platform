"""
SSH Connection Pool for efficient device management.

Maintains reusable SSH connections to reduce connection overhead
and prevent SSH session exhaustion on network devices.

Usage:
    from core.connection_pool import get_connection_pool, pooled_connection

    # Using context manager (recommended)
    async with pooled_connection("R1") as conn:
        response = await conn.send_command("show version")

    # Manual acquire/release
    pool = get_connection_pool()
    conn = await pool.acquire("R1")
    try:
        response = await conn.send_command("show version")
    finally:
        await pool.release("R1", conn)

    # Pool statistics
    stats = pool.get_stats()
"""

import asyncio
import logging
import random
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import AsyncIterator, Callable, Coroutine, Optional, Union

from scrapli.driver.core import AsyncIOSXEDriver
from scrapli.driver.generic import AsyncGenericDriver

from config.devices import DEVICES, get_scrapli_device, SSH_STRICT_KEY

logger = logging.getLogger(__name__)

# Type alias for any async Scrapli driver
AsyncDriver = Union[AsyncIOSXEDriver, AsyncGenericDriver]


@dataclass
class PooledConnection:
    """Wrapper for a pooled SSH connection with metadata."""
    driver: AsyncDriver
    device_name: str
    conn_id: int = field(default_factory=lambda: id(object()))
    created_at: float = field(default_factory=time.time)
    last_used: float = field(default_factory=time.time)
    use_count: int = 0

    def __hash__(self):
        return self.conn_id

    def __eq__(self, other):
        if isinstance(other, PooledConnection):
            return self.conn_id == other.conn_id
        return False

    def touch(self):
        """Update last_used timestamp and increment use count."""
        self.last_used = time.time()
        self.use_count += 1

    @property
    def age_seconds(self) -> float:
        """How long since this connection was created."""
        return time.time() - self.created_at

    @property
    def idle_seconds(self) -> float:
        """How long since this connection was last used."""
        return time.time() - self.last_used


class ConnectionPool:
    """
    Async SSH connection pool for network devices.

    Maintains a pool of reusable connections per device to:
    - Reduce SSH handshake overhead
    - Prevent connection exhaustion on devices
    - Improve response times for repeated operations
    """

    def __init__(
        self,
        max_per_device: int = 3,
        max_idle_seconds: int = 300,
        max_age_seconds: int = 600,
        max_retries: int = 3,
        base_delay: float = 0.5,
    ):
        """
        Initialize the connection pool.

        Args:
            max_per_device: Maximum connections per device (default: 3)
            max_idle_seconds: Close connections idle longer than this (default: 300s)
            max_age_seconds: Close connections older than this (default: 600s)
            max_retries: Maximum connection attempts before giving up (default: 3)
            base_delay: Base delay in seconds for exponential backoff (default: 0.5)
        """
        self.max_per_device = max_per_device
        self.max_idle_seconds = max_idle_seconds
        self.max_age_seconds = max_age_seconds
        self.max_retries = max_retries
        self.base_delay = base_delay

        # Pool storage: device_name -> list of available PooledConnections
        self._pools: dict[str, list[PooledConnection]] = {}

        # Track connections currently in use
        self._in_use: dict[str, set[PooledConnection]] = {}

        # Lock for thread-safe pool operations
        self._lock = asyncio.Lock()

        # Per-device circuit breakers (lazy-loaded)
        self._breakers: dict = {}

        # Statistics
        self._stats = {
            "connections_created": 0,
            "connections_reused": 0,
            "connections_closed": 0,
            "connections_failed": 0,
            "connections_retried": 0,
            "acquire_waits": 0,
        }

        logger.info(
            f"ConnectionPool initialized: max_per_device={max_per_device}, "
            f"max_idle={max_idle_seconds}s, max_age={max_age_seconds}s, "
            f"max_retries={max_retries}"
        )

    async def acquire(self, device_name: str) -> AsyncDriver:
        """
        Acquire a connection from the pool.

        Returns an existing connection if available, or creates a new one.
        In demo mode, returns a DemoConnection instead.

        Args:
            device_name: Name of the device (e.g., "R1")

        Returns:
            Scrapli async driver (IOSXEDriver or GenericDriver)

        Raises:
            ValueError: If device not found
            ConnectionError: If unable to connect
        """
        from core.demo import DEMO_MODE
        if DEMO_MODE:
            from core.demo.connection import DemoConnection
            return DemoConnection(device_name)

        if device_name not in DEVICES:
            raise ValueError(f"Device '{device_name}' not found in inventory")

        async with self._lock:
            # Initialize pool structures for this device
            if device_name not in self._pools:
                self._pools[device_name] = []
                self._in_use[device_name] = set()

            pool = self._pools[device_name]
            in_use = self._in_use[device_name]

            # Try to get an existing connection from the pool
            while pool:
                pooled_conn = pool.pop(0)

                # Check if connection is still valid
                if self._is_connection_valid(pooled_conn):
                    pooled_conn.touch()
                    in_use.add(pooled_conn)
                    self._stats["connections_reused"] += 1
                    logger.debug(
                        f"Reusing connection for {device_name} "
                        f"(use_count={pooled_conn.use_count})"
                    )
                    return pooled_conn.driver
                else:
                    # Connection expired, close it
                    await self._close_connection(pooled_conn)

            # Check if we can create a new connection
            total_for_device = len(pool) + len(in_use)
            if total_for_device >= self.max_per_device:
                self._stats["acquire_waits"] += 1
                logger.warning(
                    f"Connection limit reached for {device_name} "
                    f"({total_for_device}/{self.max_per_device})"
                )
                # Wait and retry (simple backoff)
                # Release lock while waiting
                pass  # Fall through to create new connection anyway for now

            # Create new connection
            pooled_conn = await self._create_connection(device_name)
            in_use.add(pooled_conn)
            return pooled_conn.driver

    async def release(self, device_name: str, driver: AsyncDriver):
        """
        Return a connection to the pool.

        Args:
            device_name: Name of the device
            driver: The driver to return
        """
        from core.demo import DEMO_MODE
        if DEMO_MODE:
            return  # Nothing to release for demo connections

        async with self._lock:
            if device_name not in self._in_use:
                logger.warning(f"Release called for unknown device: {device_name}")
                return

            # Find the pooled connection wrapper
            in_use = self._in_use[device_name]
            pooled_conn = None
            for pc in in_use:
                if pc.driver is driver:
                    pooled_conn = pc
                    break

            if pooled_conn is None:
                logger.warning(f"Release called for untracked connection: {device_name}")
                return

            in_use.discard(pooled_conn)

            # Check if connection should be returned to pool or closed
            if self._is_connection_valid(pooled_conn):
                self._pools[device_name].append(pooled_conn)
                logger.debug(f"Connection returned to pool for {device_name}")
            else:
                await self._close_connection(pooled_conn)

    def _is_connection_valid(self, pooled_conn: PooledConnection) -> bool:
        """Check if a connection is still valid for reuse."""
        if pooled_conn.idle_seconds > self.max_idle_seconds:
            logger.debug(
                f"Connection idle too long: {pooled_conn.idle_seconds:.0f}s > "
                f"{self.max_idle_seconds}s"
            )
            return False

        if pooled_conn.age_seconds > self.max_age_seconds:
            logger.debug(
                f"Connection too old: {pooled_conn.age_seconds:.0f}s > "
                f"{self.max_age_seconds}s"
            )
            return False

        # Check if the SSH transport is actually alive
        try:
            if not pooled_conn.driver.isalive():
                logger.debug(
                    f"Connection transport dead for {pooled_conn.device_name}"
                )
                return False
        except Exception:
            return False

        return True

    def _get_breaker(self, device_name: str):
        """Get or create a circuit breaker for a device."""
        if device_name not in self._breakers:
            from core.circuit_breaker import get_circuit_breaker
            self._breakers[device_name] = get_circuit_breaker(f"ssh:{device_name}")
        return self._breakers[device_name]

    async def _with_retries(
        self,
        coro_factory: Callable[[], Coroutine],
        device_name: str,
    ):
        """
        Execute an async operation with retry, backoff, and circuit breaker.

        Args:
            coro_factory: Zero-arg callable that returns a new coroutine each attempt
            device_name: Device name for circuit breaker lookup and logging

        Returns:
            Result of the coroutine

        Raises:
            ConnectionError: If circuit is open or all retries exhausted
        """
        breaker = self._get_breaker(device_name)
        last_exc = None

        for attempt in range(self.max_retries):
            if not breaker.allow_request():
                self._stats["connections_failed"] += 1
                raise ConnectionError(
                    f"Circuit breaker open for ssh:{device_name}, skipping connection"
                )

            try:
                result = await coro_factory()
                breaker.record_success()
                return result
            except Exception as e:
                last_exc = e
                breaker.record_failure()

                if attempt < self.max_retries - 1:
                    self._stats["connections_retried"] += 1
                    delay = self.base_delay * (2 ** attempt) + random.uniform(0, 0.5)
                    logger.warning(
                        f"Connection to {device_name} failed (attempt {attempt + 1}/"
                        f"{self.max_retries}), retrying in {delay:.1f}s: {e}"
                    )
                    await asyncio.sleep(delay)

        self._stats["connections_failed"] += 1
        raise ConnectionError(
            f"Failed to connect to {device_name} after {self.max_retries} attempts: {last_exc}"
        )

    async def _create_connection(self, device_name: str) -> PooledConnection:
        """Create a new SSH connection to a device with retry and circuit breaker."""
        device = DEVICES.get(device_name, {})
        device_type = device.get("device_type", "cisco_xe")
        scrapli_params = get_scrapli_device(device_name)

        # Remove device_type from params (not a scrapli param)
        conn_params = {k: v for k, v in scrapli_params.items() if k != "device_type"}

        async def _open_connection():
            if device_type == "linux":
                driver = AsyncGenericDriver(
                    host=conn_params["host"],
                    auth_username=conn_params["auth_username"],
                    auth_password=conn_params["auth_password"],
                    auth_strict_key=SSH_STRICT_KEY,
                    transport="asyncssh",
                    timeout_socket=10,
                    timeout_transport=10,
                )
            else:
                driver = AsyncIOSXEDriver(**conn_params)
            await driver.open()
            return driver

        driver = await self._with_retries(_open_connection, device_name)

        self._stats["connections_created"] += 1
        logger.info(f"Created new connection for {device_name}")

        return PooledConnection(driver=driver, device_name=device_name)

    async def _close_connection(self, pooled_conn: PooledConnection):
        """Close a connection and clean up."""
        try:
            await pooled_conn.driver.close()
            self._stats["connections_closed"] += 1
            logger.debug(
                f"Closed connection for {pooled_conn.device_name} "
                f"(age={pooled_conn.age_seconds:.0f}s, uses={pooled_conn.use_count})"
            )
        except Exception as e:
            logger.warning(f"Error closing connection: {e}")

    async def cleanup_idle(self):
        """Close all idle connections that have expired."""
        async with self._lock:
            closed_count = 0
            for device_name, pool in self._pools.items():
                valid_connections = []
                for pooled_conn in pool:
                    if self._is_connection_valid(pooled_conn):
                        valid_connections.append(pooled_conn)
                    else:
                        await self._close_connection(pooled_conn)
                        closed_count += 1
                self._pools[device_name] = valid_connections

            if closed_count > 0:
                logger.info(f"Cleanup closed {closed_count} idle connections")

            return closed_count

    async def close_all(self):
        """Close all connections in the pool."""
        async with self._lock:
            total_closed = 0

            # Close pooled connections
            for device_name, pool in self._pools.items():
                for pooled_conn in pool:
                    await self._close_connection(pooled_conn)
                    total_closed += 1
                pool.clear()

            # Close in-use connections (shouldn't happen normally)
            for device_name, in_use in self._in_use.items():
                for pooled_conn in in_use:
                    await self._close_connection(pooled_conn)
                    total_closed += 1
                in_use.clear()

            logger.info(f"Closed all {total_closed} connections")
            return total_closed

    def get_stats(self) -> dict:
        """Get pool statistics."""
        pool_sizes = {name: len(pool) for name, pool in self._pools.items()}
        in_use_sizes = {name: len(conns) for name, conns in self._in_use.items()}

        return {
            **self._stats,
            "pool_sizes": pool_sizes,
            "in_use_sizes": in_use_sizes,
            "total_pooled": sum(pool_sizes.values()),
            "total_in_use": sum(in_use_sizes.values()),
            "hit_rate": (
                self._stats["connections_reused"] /
                max(1, self._stats["connections_created"] + self._stats["connections_reused"])
            ) * 100,
        }


# Global pool instance
_connection_pool: Optional[ConnectionPool] = None


def get_connection_pool() -> ConnectionPool:
    """Get the global connection pool instance."""
    global _connection_pool
    if _connection_pool is None:
        _connection_pool = ConnectionPool()
    return _connection_pool


@asynccontextmanager
async def pooled_connection(device_name: str) -> AsyncIterator[AsyncDriver]:
    """
    Async context manager for pooled connections.

    Usage:
        async with pooled_connection("R1") as conn:
            response = await conn.send_command("show version")
            print(response.result)
    """
    pool = get_connection_pool()
    conn = await pool.acquire(device_name)
    try:
        yield conn
    finally:
        await pool.release(device_name, conn)


async def pool_stats() -> dict:
    """Get connection pool statistics."""
    return get_connection_pool().get_stats()


async def pool_cleanup() -> int:
    """Run pool cleanup and return number of connections closed."""
    return await get_connection_pool().cleanup_idle()


async def pool_close_all() -> int:
    """Close all pooled connections."""
    return await get_connection_pool().close_all()
