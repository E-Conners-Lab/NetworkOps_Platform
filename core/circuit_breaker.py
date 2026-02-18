"""
Circuit breaker pattern implementation for external service protection.

Prevents cascading failures by temporarily stopping calls to failing services.
Uses Redis for shared state in multi-instance deployments with in-memory fallback.
"""

import logging
import os
import time
from dataclasses import dataclass
from enum import Enum
from typing import Any, Callable, Optional, TypeVar

logger = logging.getLogger(__name__)

# Configuration
REDIS_URL = os.getenv('REDIS_URL', 'redis://localhost:6379/0')
DEFAULT_FAILURE_THRESHOLD = int(os.getenv('CIRCUIT_BREAKER_FAILURE_THRESHOLD', '3'))
DEFAULT_RECOVERY_TIMEOUT = int(os.getenv('CIRCUIT_BREAKER_RECOVERY_TIMEOUT', '60'))


class CircuitState(Enum):
    """Circuit breaker states."""
    CLOSED = "closed"      # Normal operation
    OPEN = "open"          # Blocking calls
    HALF_OPEN = "half_open"  # Testing recovery


@dataclass
class CircuitStatus:
    """Circuit breaker status information."""
    state: CircuitState
    failure_count: int
    last_failure_time: Optional[float]
    opened_at: Optional[float]
    service_name: str

    @property
    def is_allowing_requests(self) -> bool:
        """Check if requests should be allowed."""
        return self.state in (CircuitState.CLOSED, CircuitState.HALF_OPEN)


class CircuitBreaker:
    """
    Circuit breaker for protecting external service calls.

    States:
    - CLOSED: Normal operation, requests pass through
    - OPEN: Requests fail fast without calling service
    - HALF_OPEN: Single test request allowed to check recovery

    Usage:
        breaker = CircuitBreaker("netbox")

        @breaker.protect
        def call_netbox_api():
            return requests.get("http://netbox/api/...")

        # Or manual usage:
        if breaker.allow_request():
            try:
                result = call_api()
                breaker.record_success()
            except Exception as e:
                breaker.record_failure()
    """

    def __init__(
        self,
        service_name: str,
        failure_threshold: int = DEFAULT_FAILURE_THRESHOLD,
        recovery_timeout: int = DEFAULT_RECOVERY_TIMEOUT,
        use_redis: bool = True,
    ):
        """
        Initialize circuit breaker.

        Args:
            service_name: Name of the protected service (for logging and Redis key)
            failure_threshold: Number of failures before opening circuit
            recovery_timeout: Seconds before attempting recovery
            use_redis: Use Redis for shared state (falls back to in-memory)
        """
        self.service_name = service_name
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.use_redis = use_redis

        # In-memory state (fallback)
        self._state = CircuitState.CLOSED
        self._failure_count = 0
        self._last_failure_time: Optional[float] = None
        self._opened_at: Optional[float] = None

        # Redis connection (lazy loaded)
        self._redis = None

    @property
    def _redis_key(self) -> str:
        """Redis key for this circuit breaker."""
        return f"circuit_breaker:{self.service_name}"

    def _get_redis(self):
        """Get Redis connection, returns None if unavailable."""
        if not self.use_redis:
            return None

        if self._redis is not None:
            return self._redis

        try:
            import redis
            self._redis = redis.from_url(REDIS_URL, socket_timeout=1.0)
            self._redis.ping()
            return self._redis
        except Exception as e:
            logger.debug(f"Redis unavailable for circuit breaker, using in-memory: {e}")
            return None

    def _get_state_from_redis(self) -> Optional[dict]:
        """Get state from Redis if available."""
        r = self._get_redis()
        if not r:
            return None

        try:
            data = r.hgetall(self._redis_key)
            if not data:
                return None

            return {
                "state": data.get(b"state", b"closed").decode(),
                "failure_count": int(data.get(b"failure_count", b"0")),
                "last_failure_time": float(data.get(b"last_failure_time", b"0")) or None,
                "opened_at": float(data.get(b"opened_at", b"0")) or None,
            }
        except Exception as e:
            logger.warning(f"Failed to get circuit state from Redis: {e}")
            return None

    def _set_state_in_redis(self, state: str, failure_count: int, opened_at: Optional[float] = None):
        """Set state in Redis if available."""
        r = self._get_redis()
        if not r:
            return

        try:
            data = {
                "state": state,
                "failure_count": str(failure_count),
                "last_failure_time": str(time.time()),
                "opened_at": str(opened_at or 0),
            }
            r.hset(self._redis_key, mapping=data)
            r.expire(self._redis_key, self.recovery_timeout * 2)  # Auto-cleanup
        except Exception as e:
            logger.warning(f"Failed to set circuit state in Redis: {e}")

    def get_status(self) -> CircuitStatus:
        """Get current circuit breaker status."""
        # Try Redis first
        redis_state = self._get_state_from_redis()
        if redis_state:
            state = CircuitState(redis_state["state"])

            # Check if should transition from OPEN to HALF_OPEN
            if state == CircuitState.OPEN:
                opened_at = redis_state["opened_at"]
                if opened_at and (time.time() - opened_at) > self.recovery_timeout:
                    state = CircuitState.HALF_OPEN

            return CircuitStatus(
                state=state,
                failure_count=redis_state["failure_count"],
                last_failure_time=redis_state["last_failure_time"],
                opened_at=redis_state["opened_at"],
                service_name=self.service_name,
            )

        # Fall back to in-memory
        state = self._state

        # Check if should transition from OPEN to HALF_OPEN
        if state == CircuitState.OPEN and self._opened_at:
            if (time.time() - self._opened_at) > self.recovery_timeout:
                state = CircuitState.HALF_OPEN

        return CircuitStatus(
            state=state,
            failure_count=self._failure_count,
            last_failure_time=self._last_failure_time,
            opened_at=self._opened_at,
            service_name=self.service_name,
        )

    def allow_request(self) -> bool:
        """
        Check if a request should be allowed.

        Returns:
            True if request should proceed, False if circuit is open
        """
        status = self.get_status()

        if status.state == CircuitState.CLOSED:
            return True

        if status.state == CircuitState.HALF_OPEN:
            # Allow single test request
            logger.info(f"Circuit {self.service_name}: HALF_OPEN - allowing test request")
            return True

        # Circuit is OPEN
        logger.debug(f"Circuit {self.service_name}: OPEN - blocking request")
        return False

    def record_success(self):
        """Record a successful service call."""
        status = self.get_status()

        if status.state == CircuitState.HALF_OPEN:
            # Recovery successful - close circuit
            logger.info(f"Circuit {self.service_name}: recovery successful, closing circuit")
            self._state = CircuitState.CLOSED
            self._failure_count = 0
            self._opened_at = None
            self._set_state_in_redis("closed", 0, None)
        elif status.state == CircuitState.CLOSED:
            # Reset failure count on success
            if self._failure_count > 0:
                self._failure_count = 0
                self._set_state_in_redis("closed", 0, None)

    def record_failure(self):
        """Record a failed service call."""
        self._failure_count += 1
        self._last_failure_time = time.time()

        status = self.get_status()

        if status.state == CircuitState.HALF_OPEN:
            # Recovery failed - reopen circuit
            logger.warning(f"Circuit {self.service_name}: recovery failed, reopening circuit")
            self._state = CircuitState.OPEN
            self._opened_at = time.time()
            self._set_state_in_redis("open", self._failure_count, self._opened_at)
        elif self._failure_count >= self.failure_threshold:
            # Threshold exceeded - open circuit
            logger.warning(
                f"Circuit {self.service_name}: failure threshold reached "
                f"({self._failure_count}/{self.failure_threshold}), opening circuit"
            )
            self._state = CircuitState.OPEN
            self._opened_at = time.time()
            self._set_state_in_redis("open", self._failure_count, self._opened_at)
        else:
            # Update failure count
            self._set_state_in_redis("closed", self._failure_count, None)

    def reset(self):
        """Manually reset the circuit breaker."""
        logger.info(f"Circuit {self.service_name}: manual reset")
        self._state = CircuitState.CLOSED
        self._failure_count = 0
        self._last_failure_time = None
        self._opened_at = None
        self._set_state_in_redis("closed", 0, None)

    def protect(self, fallback: Optional[Callable] = None):
        """
        Decorator to protect a function with circuit breaker.

        Args:
            fallback: Optional function to call when circuit is open

        Usage:
            breaker = CircuitBreaker("myservice")

            @breaker.protect(fallback=lambda: {"error": "service unavailable"})
            def call_api():
                return requests.get("http://myservice/api").json()
        """
        def decorator(func: Callable) -> Callable:
            def wrapper(*args, **kwargs):
                if not self.allow_request():
                    if fallback:
                        return fallback()
                    raise CircuitOpenError(
                        f"Circuit breaker {self.service_name} is OPEN"
                    )

                try:
                    result = func(*args, **kwargs)
                    self.record_success()
                    return result
                except Exception as e:
                    self.record_failure()
                    raise

            return wrapper
        return decorator


class CircuitOpenError(Exception):
    """Raised when attempting to call a service with an open circuit."""
    pass


# Registry of circuit breakers for global access
_circuit_breakers: dict[str, CircuitBreaker] = {}


def get_circuit_breaker(
    service_name: str,
    failure_threshold: int = DEFAULT_FAILURE_THRESHOLD,
    recovery_timeout: int = DEFAULT_RECOVERY_TIMEOUT,
) -> CircuitBreaker:
    """
    Get or create a circuit breaker for a service.

    Args:
        service_name: Name of the service
        failure_threshold: Number of failures before opening
        recovery_timeout: Seconds before recovery attempt

    Returns:
        CircuitBreaker instance
    """
    if service_name not in _circuit_breakers:
        _circuit_breakers[service_name] = CircuitBreaker(
            service_name=service_name,
            failure_threshold=failure_threshold,
            recovery_timeout=recovery_timeout,
        )
    return _circuit_breakers[service_name]


def get_all_circuit_status() -> dict[str, CircuitStatus]:
    """Get status of all registered circuit breakers."""
    return {
        name: breaker.get_status()
        for name, breaker in _circuit_breakers.items()
    }
