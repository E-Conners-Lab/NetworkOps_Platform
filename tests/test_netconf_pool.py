"""Tests for NETCONF connection pool."""

import time
from unittest.mock import MagicMock, patch

import pytest

from core.netconf_pool import (
    NetconfConnectionPool,
    PooledNetconfConnection,
    pooled_netconf_connection,
)


def _make_mock_manager(connected=True):
    mgr = MagicMock()
    mgr.connected = connected
    return mgr


@pytest.fixture
def pool():
    """Create a fresh pool for each test."""
    return NetconfConnectionPool(
        max_per_device=2,
        max_idle_seconds=120,
        max_age_seconds=300,
    )


@pytest.fixture
def mock_connect():
    """Patch ncclient.manager.connect and _get_netconf_params."""
    with patch("core.netconf_pool.ncclient_mgr") as mock_mgr_mod, \
         patch("core.netconf_pool._get_netconf_params") as mock_params:
        mock_params.return_value = {
            "host": "10.255.255.11",
            "port": 830,
            "username": "admin",
            "password": "admin",
            "hostkey_verify": False,
            "timeout": 10,
            "device_params": {"name": "iosxe"},
        }
        mock_mgr_mod.connect.side_effect = lambda **kw: _make_mock_manager()
        yield mock_mgr_mod


class TestPooledNetconfConnection:
    def test_touch_increments_use_count(self):
        mgr = _make_mock_manager()
        pc = PooledNetconfConnection(manager=mgr, device_name="R1")
        assert pc.use_count == 0
        pc.touch()
        assert pc.use_count == 1

    def test_age_and_idle(self):
        mgr = _make_mock_manager()
        pc = PooledNetconfConnection(manager=mgr, device_name="R1")
        assert pc.age_seconds >= 0
        assert pc.idle_seconds >= 0


class TestNetconfConnectionPool:
    def test_acquire_creates_connection(self, pool, mock_connect):
        mgr = pool.acquire("R1")
        assert mgr is not None
        assert mgr.connected
        stats = pool.get_stats()
        assert stats["netconf_pool_misses_total"] == 1
        assert stats["netconf_pool_active_connections"] == 1

    def test_acquire_release_reuse(self, pool, mock_connect):
        mgr1 = pool.acquire("R1")
        pool.release("R1", mgr1)

        mgr2 = pool.acquire("R1")
        # Should reuse the same manager
        assert mgr2 is mgr1
        stats = pool.get_stats()
        assert stats["netconf_pool_hits_total"] == 1
        assert stats["netconf_pool_misses_total"] == 1

    def test_disconnected_connection_replaced(self, pool, mock_connect):
        mgr1 = pool.acquire("R1")
        # Simulate disconnect
        mgr1.connected = False
        pool.release("R1", mgr1)

        # Next acquire should create new (disconnected one evicted)
        mgr2 = pool.acquire("R1")
        assert mgr2 is not mgr1
        stats = pool.get_stats()
        assert stats["netconf_pool_evictions_total"] >= 1

    def test_idle_eviction(self, mock_connect):
        pool = NetconfConnectionPool(
            max_per_device=2,
            max_idle_seconds=0,  # immediate idle eviction
            max_age_seconds=300,
        )
        mgr1 = pool.acquire("R1")
        pool.release("R1", mgr1)
        time.sleep(0.01)

        # Should evict idle connection
        mgr2 = pool.acquire("R1")
        assert mgr2 is not mgr1
        stats = pool.get_stats()
        assert stats["netconf_pool_evictions_total"] >= 1

    def test_max_age_eviction(self, mock_connect):
        pool = NetconfConnectionPool(
            max_per_device=2,
            max_idle_seconds=120,
            max_age_seconds=0,  # immediate age eviction
        )
        mgr1 = pool.acquire("R1")
        pool.release("R1", mgr1)
        time.sleep(0.01)

        mgr2 = pool.acquire("R1")
        assert mgr2 is not mgr1

    def test_close_all(self, pool, mock_connect):
        mgr1 = pool.acquire("R1")
        pool.release("R1", mgr1)
        mgr2 = pool.acquire("R2")
        pool.release("R2", mgr2)

        pool.close_all()
        stats = pool.get_stats()
        assert stats["total_pooled"] == 0
        assert stats["netconf_pool_active_connections"] == 0

    def test_cleanup_idle(self, mock_connect):
        pool = NetconfConnectionPool(
            max_per_device=2,
            max_idle_seconds=120,
            max_age_seconds=300,
        )
        mgr = pool.acquire("R1")
        pool.release("R1", mgr)

        # Manually age the pooled connection to trigger idle eviction
        for pooled in pool._pools.get("R1", []):
            pooled.last_used = time.time() - 200  # 200s idle > 120s max

        closed = pool.cleanup_idle()
        assert closed >= 1
        stats = pool.get_stats()
        assert stats["total_pooled"] == 0

    def test_stats_keys(self, pool, mock_connect):
        stats = pool.get_stats()
        assert "netconf_pool_hits_total" in stats
        assert "netconf_pool_misses_total" in stats
        assert "netconf_pool_evictions_total" in stats
        assert "netconf_pool_active_connections" in stats
        assert "pool_sizes" in stats
        assert "total_pooled" in stats

    def test_release_untracked_connection(self, pool):
        """Releasing an unknown manager should not crash."""
        mgr = _make_mock_manager()
        pool.release("R1", mgr)
        mgr.close_session.assert_called_once()
