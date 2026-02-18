"""
Tests for Nornir Manager - Parallel device automation.
"""

import pytest
from unittest.mock import patch, MagicMock

from core.nornir_manager import (
    NornirManager, TaskResult, AggregatedResult,
    NORNIR_PLATFORM_MAP, get_nornir, run_on_devices,
)


class TestTaskResult:
    """Tests for TaskResult dataclass"""

    def test_successful_result(self):
        """Create successful task result"""
        result = TaskResult(
            device="R1",
            success=True,
            result="show version output...",
            elapsed_time=1.5,
        )

        assert result.success is True
        assert result.device == "R1"
        assert result.error is None
        assert result.changed is False

    def test_failed_result(self):
        """Create failed task result"""
        result = TaskResult(
            device="R2",
            success=False,
            error="Connection refused",
            elapsed_time=5.0,
        )

        assert result.success is False
        assert result.error == "Connection refused"
        assert result.result is None

    def test_to_dict(self):
        """Convert result to dictionary"""
        result = TaskResult(
            device="R3",
            success=True,
            result={"version": "17.13.1"},
            changed=True,
            elapsed_time=2.567,
        )

        d = result.to_dict()

        assert d["device"] == "R3"
        assert d["success"] is True
        assert d["changed"] is True
        assert d["elapsed_time"] == 2.57  # Rounded


class TestAggregatedResult:
    """Tests for AggregatedResult dataclass"""

    def test_all_successful(self):
        """All devices succeeded"""
        result = AggregatedResult(
            task_name="show version",
            total_devices=3,
            successful=3,
            failed=0,
            elapsed_time=2.5,
        )

        assert result.all_success is True
        assert result.success_rate == 100.0
        assert result.failed_devices() == []

    def test_partial_failure(self):
        """Some devices failed"""
        results = {
            "R1": TaskResult(device="R1", success=True, result="ok"),
            "R2": TaskResult(device="R2", success=False, error="timeout"),
            "R3": TaskResult(device="R3", success=True, result="ok"),
        }

        result = AggregatedResult(
            task_name="show version",
            total_devices=3,
            successful=2,
            failed=1,
            results=results,
            elapsed_time=5.0,
        )

        assert result.all_success is False
        assert result.success_rate == pytest.approx(66.7, rel=0.1)
        assert result.failed_devices() == ["R2"]
        assert set(result.successful_devices()) == {"R1", "R3"}

    def test_to_dict(self):
        """Convert aggregated result to dictionary"""
        results = {
            "R1": TaskResult(device="R1", success=True, result="ok"),
        }

        result = AggregatedResult(
            task_name="test",
            total_devices=1,
            successful=1,
            failed=0,
            results=results,
            elapsed_time=1.0,
        )

        d = result.to_dict()

        assert d["task_name"] == "test"
        assert d["total_devices"] == 1
        assert d["all_success"] is True
        assert "R1" in d["results"]


class TestPlatformMapping:
    """Tests for platform name mapping"""

    def test_cisco_platforms(self):
        """Cisco platforms should map correctly"""
        assert NORNIR_PLATFORM_MAP["cisco_xe"] == "cisco_iosxe"
        assert NORNIR_PLATFORM_MAP["cisco_ios"] == "cisco_ios"
        assert NORNIR_PLATFORM_MAP["cisco_nxos"] == "cisco_nxos"

    def test_juniper_platform(self):
        """Juniper should map correctly"""
        assert NORNIR_PLATFORM_MAP["juniper_junos"] == "juniper_junos"

    def test_arista_platform(self):
        """Arista should map correctly"""
        assert NORNIR_PLATFORM_MAP["arista_eos"] == "arista_eos"

    def test_linux_platform(self):
        """Linux should map correctly"""
        assert NORNIR_PLATFORM_MAP["linux"] == "linux"


class TestNornirManager:
    """Tests for NornirManager class"""

    def test_load_inventory(self):
        """Should load inventory from config/devices.py"""
        manager = NornirManager()
        inventory = manager._load_inventory()

        # Should have some devices
        assert len(inventory) > 0

        # Each device should have required fields
        for name, device in inventory.items():
            assert "hostname" in device
            assert "platform" in device
            assert "username" in device
            assert "password" in device

    def test_filter_by_type(self):
        """Should filter devices by type"""
        manager = NornirManager()

        cisco_devices = manager._filter_devices(filter_type="cisco_xe")

        # All should be Cisco
        for name, device in cisco_devices.items():
            assert device.get("device_type") == "cisco_xe"

    def test_filter_by_name_list(self):
        """Should filter to specific device names"""
        manager = NornirManager()

        filtered = manager._filter_devices(devices=["R1", "R2"])

        assert "R1" in filtered or len(filtered) == 0  # If R1 exists
        assert "R3" not in filtered

    def test_filter_by_pattern(self):
        """Should filter by regex pattern"""
        manager = NornirManager()

        # Pattern to match R1, R2, R3, R4
        filtered = manager._filter_devices(filter_pattern=r"^R\d+$")

        for name in filtered:
            assert name.startswith("R")

    def test_get_inventory_summary(self):
        """Should return inventory summary"""
        manager = NornirManager()
        summary = manager.get_inventory_summary()

        assert "total_devices" in summary
        assert "by_type" in summary
        assert "nornir_available" in summary
        assert "nornir_enabled" in summary

    def test_parse_cisco_version(self):
        """Should parse Cisco show version output"""
        manager = NornirManager()

        output = """
Cisco IOS XE Software, Version 17.13.01a
R1 uptime is 5 days, 3 hours, 22 minutes
Cisco C8000V (VXE) processor with 2028924K/3075K bytes of memory.
Processor board ID 9MHWGXAL08B
"""

        facts = manager._parse_cisco_version(output)

        assert facts.get("version") == "17.13.01a"
        assert facts.get("hostname") == "R1"
        assert "5 days" in facts.get("uptime", "")
        assert facts.get("serial") == "9MHWGXAL08B"


class TestNornirManagerWithMocks:
    """Tests that require mocking external connections"""

    @patch('core.nornir_manager.is_enabled')
    def test_run_command_disabled(self, mock_enabled):
        """Should return error when Nornir disabled"""
        mock_enabled.return_value = False
        manager = NornirManager()

        result = manager.run_command("show version")

        assert result.total_devices == 0
        assert result.successful == 0

    @patch('core.nornir_manager.is_enabled')
    def test_run_config_dry_run(self, mock_enabled):
        """Dry run should not execute commands"""
        mock_enabled.return_value = True
        manager = NornirManager()

        result = manager.run_config(
            config_commands="logging host 198.51.100.1",
            devices=["R1"],
            dry_run=True,
        )

        # Dry run returns preview
        if result.total_devices > 0:
            for name, task_result in result.results.items():
                assert task_result.result.get("dry_run") is True
                assert task_result.changed is False


class TestConvenienceFunctions:
    """Tests for module-level convenience functions"""

    def test_get_nornir_singleton(self):
        """Should return same instance"""
        manager1 = get_nornir()
        manager2 = get_nornir()

        assert manager1 is manager2
        assert isinstance(manager1, NornirManager)

    @patch('core.nornir_manager.is_enabled')
    def test_run_on_devices_disabled(self, mock_enabled):
        """run_on_devices should work when disabled"""
        mock_enabled.return_value = False

        result = run_on_devices("show version")

        assert isinstance(result, AggregatedResult)
        assert result.total_devices == 0


class TestNornirManagerMaxWorkers:
    """Tests for concurrent worker configuration"""

    def test_default_max_workers(self):
        """Default max_workers should be 10"""
        manager = NornirManager()
        assert manager.max_workers == 10

    def test_custom_max_workers(self):
        """Should accept custom max_workers"""
        manager = NornirManager(max_workers=5)
        assert manager.max_workers == 5


class TestNornirAvailability:
    """Tests for Nornir availability detection"""

    def test_nornir_available_property(self):
        """Should detect Nornir availability"""
        manager = NornirManager()

        # Just check it doesn't crash
        available = manager.nornir_available
        assert isinstance(available, bool)

    def test_nornir_available_cached(self):
        """Should cache availability check"""
        manager = NornirManager()

        # First call
        result1 = manager.nornir_available
        # Second call (should use cache)
        result2 = manager.nornir_available

        assert result1 == result2


class TestMultipleFilters:
    """Tests for combining multiple filters"""

    def test_type_and_pattern_filter(self):
        """Should combine type and pattern filters"""
        manager = NornirManager()

        # Filter Cisco devices matching R* pattern
        filtered = manager._filter_devices(
            filter_type="cisco_xe",
            filter_pattern=r"^R\d+$",
        )

        for name, device in filtered.items():
            assert device.get("device_type") == "cisco_xe"
            assert name.startswith("R")

    def test_devices_and_type_filter(self):
        """Should combine device list and type filter"""
        manager = NornirManager()

        # This should return empty if types don't match
        filtered = manager._filter_devices(
            devices=["R1", "R2"],
            filter_type="linux",  # R1, R2 are not Linux
        )

        # Should be empty since R1, R2 are cisco_xe not linux
        assert len(filtered) == 0


class TestCustomFilter:
    """Tests for custom filter function"""

    def test_custom_filter_function(self):
        """Should support custom filter function"""
        manager = NornirManager()

        # Custom filter: only devices with IP ending in .11 or .12
        def ip_filter(name: str, device: dict) -> bool:
            hostname = device.get("hostname", "")
            return hostname.endswith(".11") or hostname.endswith(".12")

        filtered = manager._filter_devices(custom_filter=ip_filter)

        for name, device in filtered.items():
            hostname = device.get("hostname", "")
            assert hostname.endswith(".11") or hostname.endswith(".12")
