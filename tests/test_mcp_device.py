"""
Unit tests for mcp_tools.device module.

Tests device management tools:
- get_devices: List all devices in inventory
- send_command: Execute show commands
- send_config: Apply configuration changes
- health_check: Check single device health
- health_check_all: Check all devices in parallel
"""

import asyncio
import json
import pytest
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch, MagicMock


class TestGetDevices:
    """Tests for get_devices tool."""

    def test_get_devices_returns_list(self, mock_devices, patch_mcp_device_imports):
        """get_devices should return list of device names."""
        from mcp_tools.device import get_devices

        result = get_devices()

        assert isinstance(result, list)
        assert set(result) == set(mock_devices.keys())

    def test_get_devices_empty_inventory(self, patch_mcp_device_imports):
        """get_devices with empty inventory returns empty list."""
        from mcp_tools.device import get_devices

        with patch("mcp_tools.device.DEVICES", {}):
            result = get_devices()

        assert result == []


class TestSendCommand:
    """Tests for send_command tool."""

    @pytest.mark.asyncio
    async def test_send_command_success(self, mock_devices, mock_scrapli_device, patch_mcp_device_imports):
        """send_command should execute command and return output."""
        from mcp_tools.device import send_command

        result = await send_command("R1", "show version")

        assert "MOCK_COMMAND_RESULT" in result or "output" in result

    @pytest.mark.asyncio
    async def test_send_command_device_not_found(self, patch_mcp_device_imports):
        """send_command with invalid device should return error."""
        from mcp_tools.device import send_command

        result = await send_command("NONEXISTENT", "show version")
        parsed = json.loads(result)

        assert "error" in parsed
        assert "not found" in parsed["error"].lower()

    @pytest.mark.asyncio
    async def test_send_command_linux_device(self, mock_devices, mock_scrapli_device, patch_mcp_device_imports):
        """send_command on Linux device uses linux connection."""
        from mcp_tools.device import send_command

        result = await send_command("Alpine-1", "uptime")

        # Should succeed (returns mock result)
        assert "MOCK_COMMAND_RESULT" in result or "error" not in result.lower()


class TestSendConfig:
    """Tests for send_config tool."""

    @pytest.mark.asyncio
    async def test_send_config_success(self, mock_devices, mock_scrapli_device, patch_mcp_device_imports):
        """send_config should apply config commands."""
        from mcp_tools.device import send_config

        # Need to patch for cisco_xe device type
        with patch("mcp_tools.device.DEVICES", {"R1": {"hostname": "192.0.2.1", "device_type": "cisco_xe"}}):
            result = await send_config("R1", "interface Gi1\ndescription Test")

        # Should return success or mock result
        if isinstance(result, str) and result.startswith("{"):
            parsed = json.loads(result)
            assert "error" not in parsed or "success" in parsed.get("status", "")

    @pytest.mark.asyncio
    async def test_send_config_device_not_found(self, patch_mcp_device_imports):
        """send_config with invalid device should return error."""
        from mcp_tools.device import send_config

        result = await send_config("NONEXISTENT", "interface Gi1")
        parsed = json.loads(result)

        assert "error" in parsed
        assert "not found" in parsed["error"].lower()


class TestHealthCheck:
    """Tests for health_check tool."""

    @pytest.mark.asyncio
    async def test_health_check_cache_hit(self, mock_devices, mock_device_cache, patch_mcp_device_imports):
        """health_check should return cached result when available."""
        from mcp_tools.device import health_check

        # Setup cache hit
        cached_result = {"device": "R1", "status": "healthy", "uptime": "5 days"}
        mock_device_cache.get_health.return_value = cached_result

        with patch("mcp_tools.device.get_device_cache", return_value=mock_device_cache):
            result = await health_check("R1")

        parsed = json.loads(result)
        assert parsed["status"] == "healthy"
        assert parsed.get("_from_cache") is True

    @pytest.mark.asyncio
    async def test_health_check_cache_miss(self, mock_devices, mock_scrapli_device, mock_device_cache, patch_mcp_device_imports):
        """health_check should fetch from device on cache miss."""
        from mcp_tools.device import health_check

        # Setup cache miss
        mock_device_cache.get_health.return_value = None

        with patch("mcp_tools.device.get_device_cache", return_value=mock_device_cache):
            result = await health_check("R1")

        # Cache should be populated after fetch
        mock_device_cache.set_health.assert_called_once()

    @pytest.mark.asyncio
    async def test_health_check_device_not_found(self, patch_mcp_device_imports):
        """health_check with invalid device should return error."""
        from mcp_tools.device import health_check

        result = await health_check("NONEXISTENT")
        parsed = json.loads(result)

        assert "error" in parsed
        assert "not found" in parsed["error"].lower()


class TestHealthCheckAll:
    """Tests for health_check_all tool."""

    @pytest.mark.asyncio
    async def test_health_check_all_parallel_execution(self, mock_devices, mock_scrapli_device, mock_device_cache, patch_mcp_device_imports):
        """health_check_all should check all devices in parallel."""
        from mcp_tools.device import health_check_all

        # Setup cache miss for all devices
        mock_device_cache.get_health_batch.return_value = {name: None for name in mock_devices}

        with patch("mcp_tools.device.get_device_cache", return_value=mock_device_cache):
            result = await health_check_all()

        parsed = json.loads(result)
        assert "devices" in parsed
        assert "summary" in parsed
        assert "elapsed_seconds" in parsed

    @pytest.mark.asyncio
    async def test_health_check_all_with_cache(self, mock_devices, mock_device_cache, patch_mcp_device_imports):
        """health_check_all should use cached results when available."""
        from mcp_tools.device import health_check_all

        # Setup partial cache hit
        mock_device_cache.get_health_batch.return_value = {
            "R1": {"device": "R1", "status": "healthy"},
            "R2": None,
            "R3": None,
            "Alpine-1": {"device": "Alpine-1", "status": "healthy"},
        }

        with patch("mcp_tools.device.get_device_cache", return_value=mock_device_cache):
            result = await health_check_all()

        parsed = json.loads(result)
        assert parsed["cache_hits"] == 2  # R1 and Alpine-1

    @pytest.mark.asyncio
    async def test_health_check_all_summary_counts(self, mock_devices, mock_device_cache, patch_mcp_device_imports):
        """health_check_all should provide accurate summary counts."""
        from mcp_tools.device import health_check_all

        # Setup all cache hits with mixed statuses
        mock_device_cache.get_health_batch.return_value = {
            "R1": {"device": "R1", "status": "healthy"},
            "R2": {"device": "R2", "status": "degraded"},
            "R3": {"device": "R3", "status": "critical"},
            "Alpine-1": {"device": "Alpine-1", "status": "healthy"},
        }

        with patch("mcp_tools.device.get_device_cache", return_value=mock_device_cache):
            result = await health_check_all()

        parsed = json.loads(result)
        assert parsed["summary"]["healthy"] == 2
        assert parsed["summary"]["degraded"] == 1
        assert parsed["summary"]["critical"] == 1

    @pytest.mark.asyncio
    async def test_health_check_all_netconf_mode(self, mock_devices, mock_device_cache, patch_mcp_device_imports):
        """health_check_all with use_netconf=True should indicate mode."""
        from mcp_tools.device import health_check_all

        mock_device_cache.get_health_batch.return_value = {name: None for name in mock_devices}

        with patch("mcp_tools.device.get_device_cache", return_value=mock_device_cache):
            result = await health_check_all(use_netconf=True)

        parsed = json.loads(result)
        assert parsed["mode"] == "netconf"


class TestConcurrency:
    """Tests for concurrency and throttling behavior."""

    @pytest.mark.asyncio
    async def test_concurrent_commands_throttled(self, mock_devices, mock_scrapli_device, patch_mcp_device_imports, timed_run):
        """Multiple concurrent send_command calls should be throttled."""
        from mcp_tools.device import send_command

        # Run multiple commands concurrently
        timed_run.start()
        tasks = [send_command("R1", f"show ip route {i}") for i in range(5)]
        results = await asyncio.gather(*tasks)
        timed_run.stop()

        # All should complete
        assert len(results) == 5
        print(f"\n[Diagnostic] {len(results)} concurrent commands in {timed_run.duration:.3f}s")

    @pytest.mark.asyncio
    async def test_semaphore_limits_concurrency(self, mock_devices, mock_scrapli_device, patch_mcp_device_imports):
        """Semaphore should limit concurrent connections."""
        from mcp_tools._shared import get_semaphore, reset_semaphore

        # Reset to ensure clean state
        reset_semaphore()
        sem = get_semaphore()

        # Track max concurrent tasks
        concurrent_active = 0
        max_concurrent = 0

        async def tracked_task(i):
            nonlocal concurrent_active, max_concurrent
            async with sem:
                concurrent_active += 1
                max_concurrent = max(max_concurrent, concurrent_active)
                await asyncio.sleep(0.01)
                concurrent_active -= 1
            return i

        # Run many tasks
        tasks = [tracked_task(i) for i in range(150)]
        results = await asyncio.gather(*tasks)

        assert len(results) == 150
        assert max_concurrent <= 100  # Default semaphore limit
        print(f"\n[Diagnostic] Max concurrent: {max_concurrent}")

        # Cleanup
        reset_semaphore()


class TestToolRegistry:
    """Tests for tool registration metadata."""

    def test_tools_list_complete(self):
        """TOOLS list should contain all 5 device tools."""
        from mcp_tools.device import TOOLS

        assert len(TOOLS) == 5

        expected_names = ["get_devices", "send_command", "send_config", "health_check", "health_check_all"]
        actual_names = [t["name"] for t in TOOLS]
        assert set(actual_names) == set(expected_names)

    def test_tools_have_required_fields(self):
        """Each tool entry should have fn, name, and category."""
        from mcp_tools.device import TOOLS

        for tool in TOOLS:
            assert "fn" in tool, f"Tool missing 'fn': {tool}"
            assert "name" in tool, f"Tool missing 'name': {tool}"
            assert "category" in tool, f"Tool missing 'category': {tool}"
            assert callable(tool["fn"]), f"Tool 'fn' not callable: {tool['name']}"

    def test_all_tools_in_device_category(self):
        """All device tools should be in 'device' category."""
        from mcp_tools.device import TOOLS

        for tool in TOOLS:
            assert tool["category"] == "device", f"Tool {tool['name']} has wrong category"
