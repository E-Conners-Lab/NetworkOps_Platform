"""
Nornir Integration for NetworkOps

Provides parallel task execution across network devices using Nornir framework.
Integrates with existing device inventory (config/devices.py or NetBox).

Feature Flag: use_nornir (default: false)

Key Features:
- Inventory sync with config/devices.py or NetBox
- Parallel command/config execution
- Structured results with per-device status
- Device filtering by type, name pattern, or custom filters
- Integration with existing Scrapli/Netmiko connections

Usage:
    from core.nornir_manager import NornirManager, get_nornir

    nr = get_nornir()
    results = nr.run_command("show ip interface brief", filter_type="cisco_xe")

    # Or with filtering
    results = nr.run_command("show version", devices=["R1", "R2", "R3"])
"""

import logging
import re
from typing import Dict, Any, List, Optional, Callable, Union
from dataclasses import dataclass, field
from concurrent.futures import ThreadPoolExecutor, as_completed

from core.feature_flags import is_enabled

logger = logging.getLogger(__name__)


@dataclass
class TaskResult:
    """Result of a single task execution on one device"""
    device: str
    success: bool
    result: Any = None
    error: Optional[str] = None
    changed: bool = False
    elapsed_time: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "device": self.device,
            "success": self.success,
            "result": self.result,
            "error": self.error,
            "changed": self.changed,
            "elapsed_time": round(self.elapsed_time, 2),
        }


@dataclass
class AggregatedResult:
    """Aggregated results from running tasks on multiple devices"""
    task_name: str
    total_devices: int
    successful: int
    failed: int
    results: Dict[str, TaskResult] = field(default_factory=dict)
    elapsed_time: float = 0.0

    @property
    def success_rate(self) -> float:
        if self.total_devices == 0:
            return 0.0
        return (self.successful / self.total_devices) * 100

    @property
    def all_success(self) -> bool:
        return self.failed == 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "task_name": self.task_name,
            "total_devices": self.total_devices,
            "successful": self.successful,
            "failed": self.failed,
            "success_rate": round(self.success_rate, 1),
            "all_success": self.all_success,
            "elapsed_time": round(self.elapsed_time, 2),
            "results": {
                name: result.to_dict()
                for name, result in self.results.items()
            },
        }

    def failed_devices(self) -> List[str]:
        """Get list of devices that failed"""
        return [name for name, result in self.results.items() if not result.success]

    def successful_devices(self) -> List[str]:
        """Get list of devices that succeeded"""
        return [name for name, result in self.results.items() if result.success]


# Platform mapping for Nornir (aligns with ntc_parser and scrapli)
NORNIR_PLATFORM_MAP = {
    "cisco_xe": "cisco_iosxe",
    "cisco_ios": "cisco_ios",
    "cisco_nxos": "cisco_nxos",
    "cisco_xr": "cisco_iosxr",
    "juniper_junos": "juniper_junos",
    "arista_eos": "arista_eos",
    "linux": "linux",
    "aruba_aoscx": "aruba_aoscx",
    "hp_procurve": "hp_procurve",
    "hp_comware": "hp_comware",
}


class NornirManager:
    """
    Manages Nornir operations with NetworkOps inventory.

    Provides parallel task execution using either native Nornir plugins
    or fallback to direct Scrapli/Netmiko connections.
    """

    def __init__(self, max_workers: int = 10):
        """
        Initialize NornirManager.

        Args:
            max_workers: Maximum parallel connections (default: 10)
        """
        self.max_workers = max_workers
        self._nornir = None
        self._nornir_available = None
        self._inventory_loaded = False

    @property
    def nornir_available(self) -> bool:
        """Check if Nornir is installed"""
        if self._nornir_available is None:
            try:
                import nornir
                from nornir.core import Nornir
                self._nornir_available = True
                logger.debug("Nornir is available")
            except ImportError:
                self._nornir_available = False
                logger.debug("Nornir not installed")
        return self._nornir_available

    def _load_inventory(self) -> Dict[str, Dict]:
        """Load inventory from config/devices.py"""
        from config.devices import DEVICES, USERNAME, PASSWORD

        inventory = {}
        for name, device in DEVICES.items():
            device_type = device.get("device_type", "")

            # Skip containerlab devices (require special handling)
            if device_type.startswith("containerlab_"):
                continue

            platform = NORNIR_PLATFORM_MAP.get(device_type, device_type)

            inventory[name] = {
                "hostname": device.get("host", ""),
                "platform": platform,
                "username": device.get("username", USERNAME),
                "password": device.get("password", PASSWORD),
                "device_type": device_type,  # Keep original for filtering
                "data": {
                    "device_type": device_type,
                },
            }

        return inventory

    def _init_nornir(self):
        """Initialize Nornir with inventory from config/devices.py"""
        if not self.nornir_available:
            return None

        try:
            from nornir import InitNornir
            from nornir.core.inventory import (
                Hosts, Host, Groups, Group, Defaults,
                ConnectionOptions,
            )

            # Load inventory
            raw_inventory = self._load_inventory()

            # Build Nornir hosts
            hosts = Hosts()
            for name, data in raw_inventory.items():
                hosts[name] = Host(
                    name=name,
                    hostname=data["hostname"],
                    platform=data["platform"],
                    username=data["username"],
                    password=data["password"],
                    data=data.get("data", {}),
                    connection_options={
                        "scrapli": ConnectionOptions(
                            extras={
                                "auth_strict_key": False,
                                "transport": "asyncssh",
                            }
                        ),
                        "netmiko": ConnectionOptions(
                            extras={
                                "device_type": data["device_type"],
                            }
                        ),
                    },
                )

            # Create Nornir instance with DictInventory-like setup
            self._nornir = InitNornir(
                runner={
                    "plugin": "threaded",
                    "options": {
                        "num_workers": self.max_workers,
                    },
                },
                inventory={
                    "plugin": "nornir.plugins.inventory.simple.SimpleInventory",
                    "options": {
                        "host_file": None,
                        "group_file": None,
                        "defaults_file": None,
                    },
                },
                logging={"enabled": False},
            )

            # Replace with our custom inventory
            self._nornir.inventory = type(
                'Inventory', (), {
                    'hosts': hosts,
                    'groups': Groups(),
                    'defaults': Defaults(),
                }
            )()

            self._inventory_loaded = True
            logger.debug(f"Nornir initialized with {len(hosts)} hosts")
            return self._nornir

        except Exception as e:
            logger.warning(f"Failed to initialize Nornir: {e}")
            return None

    def _filter_devices(
        self,
        devices: Optional[List[str]] = None,
        filter_type: Optional[str] = None,
        filter_pattern: Optional[str] = None,
        custom_filter: Optional[Callable] = None,
    ) -> Dict[str, Dict]:
        """
        Filter devices based on criteria.

        Args:
            devices: List of specific device names
            filter_type: Filter by device_type (e.g., "cisco_xe")
            filter_pattern: Regex pattern to match device names
            custom_filter: Custom filter function(name, device) -> bool

        Returns:
            Dict of filtered devices
        """
        inventory = self._load_inventory()

        if devices:
            # Filter to specific devices
            inventory = {
                name: dev for name, dev in inventory.items()
                if name in devices
            }

        if filter_type:
            inventory = {
                name: dev for name, dev in inventory.items()
                if dev.get("device_type") == filter_type
            }

        if filter_pattern:
            pattern = re.compile(filter_pattern, re.IGNORECASE)
            inventory = {
                name: dev for name, dev in inventory.items()
                if pattern.search(name)
            }

        if custom_filter:
            inventory = {
                name: dev for name, dev in inventory.items()
                if custom_filter(name, dev)
            }

        return inventory

    def run_command(
        self,
        command: str,
        devices: Optional[List[str]] = None,
        filter_type: Optional[str] = None,
        filter_pattern: Optional[str] = None,
        use_scrapli: bool = True,
    ) -> AggregatedResult:
        """
        Run a command on multiple devices in parallel.

        Args:
            command: Command to execute
            devices: List of specific device names (optional)
            filter_type: Filter by device_type (optional)
            filter_pattern: Regex pattern for device names (optional)
            use_scrapli: Use Scrapli (True) or Netmiko (False)

        Returns:
            AggregatedResult with per-device results
        """
        if not is_enabled("use_nornir"):
            return AggregatedResult(
                task_name=f"command: {command}",
                total_devices=0,
                successful=0,
                failed=0,
                results={},
            )

        import time
        start_time = time.time()

        filtered_devices = self._filter_devices(
            devices=devices,
            filter_type=filter_type,
            filter_pattern=filter_pattern,
        )

        if not filtered_devices:
            return AggregatedResult(
                task_name=f"command: {command}",
                total_devices=0,
                successful=0,
                failed=0,
                results={},
            )

        results = {}
        successful = 0
        failed = 0

        # Execute in parallel using ThreadPoolExecutor
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {}
            for name, device in filtered_devices.items():
                future = executor.submit(
                    self._execute_command,
                    name,
                    device,
                    command,
                    use_scrapli,
                )
                futures[future] = name

            for future in as_completed(futures):
                name = futures[future]
                try:
                    result = future.result()
                    results[name] = result
                    if result.success:
                        successful += 1
                    else:
                        failed += 1
                except Exception as e:
                    results[name] = TaskResult(
                        device=name,
                        success=False,
                        error=str(e),
                    )
                    failed += 1

        elapsed = time.time() - start_time

        return AggregatedResult(
            task_name=f"command: {command}",
            total_devices=len(filtered_devices),
            successful=successful,
            failed=failed,
            results=results,
            elapsed_time=elapsed,
        )

    def _execute_command(
        self,
        name: str,
        device: Dict,
        command: str,
        use_scrapli: bool = True,
    ) -> TaskResult:
        """Execute command on a single device"""
        import time
        start = time.time()

        try:
            if use_scrapli:
                result = self._execute_with_scrapli(device, command)
            else:
                result = self._execute_with_netmiko(device, command)

            elapsed = time.time() - start
            return TaskResult(
                device=name,
                success=True,
                result=result,
                elapsed_time=elapsed,
            )
        except Exception as e:
            elapsed = time.time() - start
            return TaskResult(
                device=name,
                success=False,
                error=str(e),
                elapsed_time=elapsed,
            )

    def _execute_with_scrapli(self, device: Dict, command: str) -> str:
        """Execute command using Scrapli"""
        from scrapli import Scrapli

        platform_map = {
            "cisco_xe": "cisco_iosxe",
            "cisco_ios": "cisco_iosxe",
            "cisco_nxos": "cisco_nxos",
            "juniper_junos": "juniper_junos",
            "arista_eos": "arista_eos",
        }

        device_type = device.get("device_type", "cisco_xe")
        platform = platform_map.get(device_type, "cisco_iosxe")

        conn = Scrapli(
            host=device["hostname"],
            auth_username=device["username"],
            auth_password=device["password"],
            auth_strict_key=False,
            platform=platform,
            transport="system",
        )

        conn.open()
        try:
            response = conn.send_command(command)
            return response.result
        finally:
            conn.close()

    def _execute_with_netmiko(self, device: Dict, command: str) -> str:
        """Execute command using Netmiko"""
        from netmiko import ConnectHandler

        netmiko_device = {
            "device_type": device.get("device_type", "cisco_xe"),
            "host": device["hostname"],
            "username": device["username"],
            "password": device["password"],
        }

        conn = ConnectHandler(**netmiko_device)
        try:
            return conn.send_command(command)
        finally:
            conn.disconnect()

    def run_config(
        self,
        config_commands: Union[str, List[str]],
        devices: Optional[List[str]] = None,
        filter_type: Optional[str] = None,
        filter_pattern: Optional[str] = None,
        dry_run: bool = False,
    ) -> AggregatedResult:
        """
        Apply configuration to multiple devices in parallel.

        Args:
            config_commands: Single command or list of commands
            devices: List of specific device names (optional)
            filter_type: Filter by device_type (optional)
            filter_pattern: Regex pattern for device names (optional)
            dry_run: If True, only show what would be configured

        Returns:
            AggregatedResult with per-device results
        """
        if not is_enabled("use_nornir"):
            return AggregatedResult(
                task_name="config",
                total_devices=0,
                successful=0,
                failed=0,
                results={},
            )

        if isinstance(config_commands, str):
            config_commands = [cmd.strip() for cmd in config_commands.split(";") if cmd.strip()]

        import time
        start_time = time.time()

        filtered_devices = self._filter_devices(
            devices=devices,
            filter_type=filter_type,
            filter_pattern=filter_pattern,
        )

        if not filtered_devices:
            return AggregatedResult(
                task_name="config",
                total_devices=0,
                successful=0,
                failed=0,
                results={},
            )

        if dry_run:
            # Return what would be configured
            results = {}
            for name in filtered_devices:
                results[name] = TaskResult(
                    device=name,
                    success=True,
                    result={"dry_run": True, "commands": config_commands},
                    changed=False,
                )
            return AggregatedResult(
                task_name="config (dry-run)",
                total_devices=len(filtered_devices),
                successful=len(filtered_devices),
                failed=0,
                results=results,
                elapsed_time=0,
            )

        results = {}
        successful = 0
        failed = 0

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {}
            for name, device in filtered_devices.items():
                future = executor.submit(
                    self._execute_config,
                    name,
                    device,
                    config_commands,
                )
                futures[future] = name

            for future in as_completed(futures):
                name = futures[future]
                try:
                    result = future.result()
                    results[name] = result
                    if result.success:
                        successful += 1
                    else:
                        failed += 1
                except Exception as e:
                    results[name] = TaskResult(
                        device=name,
                        success=False,
                        error=str(e),
                    )
                    failed += 1

        elapsed = time.time() - start_time

        return AggregatedResult(
            task_name="config",
            total_devices=len(filtered_devices),
            successful=successful,
            failed=failed,
            results=results,
            elapsed_time=elapsed,
        )

    def _execute_config(
        self,
        name: str,
        device: Dict,
        commands: List[str],
    ) -> TaskResult:
        """Apply config commands to a single device"""
        import time
        start = time.time()

        try:
            from netmiko import ConnectHandler

            netmiko_device = {
                "device_type": device.get("device_type", "cisco_xe"),
                "host": device["hostname"],
                "username": device["username"],
                "password": device["password"],
            }

            conn = ConnectHandler(**netmiko_device)
            try:
                output = conn.send_config_set(commands)
                elapsed = time.time() - start
                return TaskResult(
                    device=name,
                    success=True,
                    result=output,
                    changed=True,
                    elapsed_time=elapsed,
                )
            finally:
                conn.disconnect()

        except Exception as e:
            elapsed = time.time() - start
            return TaskResult(
                device=name,
                success=False,
                error=str(e),
                elapsed_time=elapsed,
            )

    def get_facts(
        self,
        devices: Optional[List[str]] = None,
        filter_type: Optional[str] = None,
    ) -> AggregatedResult:
        """
        Gather facts (version, model, serial) from devices.

        Args:
            devices: List of specific device names (optional)
            filter_type: Filter by device_type (optional)

        Returns:
            AggregatedResult with device facts
        """
        if not is_enabled("use_nornir"):
            return AggregatedResult(
                task_name="get_facts",
                total_devices=0,
                successful=0,
                failed=0,
                results={},
            )

        import time
        start_time = time.time()

        filtered_devices = self._filter_devices(
            devices=devices,
            filter_type=filter_type,
        )

        results = {}
        successful = 0
        failed = 0

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {}
            for name, device in filtered_devices.items():
                future = executor.submit(
                    self._get_device_facts,
                    name,
                    device,
                )
                futures[future] = name

            for future in as_completed(futures):
                name = futures[future]
                try:
                    result = future.result()
                    results[name] = result
                    if result.success:
                        successful += 1
                    else:
                        failed += 1
                except Exception as e:
                    results[name] = TaskResult(
                        device=name,
                        success=False,
                        error=str(e),
                    )
                    failed += 1

        elapsed = time.time() - start_time

        return AggregatedResult(
            task_name="get_facts",
            total_devices=len(filtered_devices),
            successful=successful,
            failed=failed,
            results=results,
            elapsed_time=elapsed,
        )

    def _get_device_facts(self, name: str, device: Dict) -> TaskResult:
        """Get facts from a single device"""
        import time
        start = time.time()

        try:
            # Use show version for Cisco devices
            device_type = device.get("device_type", "")

            if device_type in ["cisco_xe", "cisco_ios"]:
                output = self._execute_with_netmiko(device, "show version")

                # Parse basic facts from output
                facts = self._parse_cisco_version(output)
                elapsed = time.time() - start

                return TaskResult(
                    device=name,
                    success=True,
                    result=facts,
                    elapsed_time=elapsed,
                )
            else:
                # Generic - just return raw output
                output = self._execute_with_netmiko(device, "show version")
                elapsed = time.time() - start

                return TaskResult(
                    device=name,
                    success=True,
                    result={"raw_output": output},
                    elapsed_time=elapsed,
                )

        except Exception as e:
            elapsed = time.time() - start
            return TaskResult(
                device=name,
                success=False,
                error=str(e),
                elapsed_time=elapsed,
            )

    def _parse_cisco_version(self, output: str) -> Dict[str, Any]:
        """Parse Cisco show version output"""
        facts = {}

        # Version
        version_match = re.search(r"Version\s+(\S+)", output)
        if version_match:
            facts["version"] = version_match.group(1)

        # Hostname
        hostname_match = re.search(r"(\S+)\s+uptime", output)
        if hostname_match:
            facts["hostname"] = hostname_match.group(1)

        # Uptime
        uptime_match = re.search(r"uptime is (.+)", output)
        if uptime_match:
            facts["uptime"] = uptime_match.group(1).strip()

        # Model
        model_match = re.search(r"[Cc]isco\s+(\S+)\s+.*processor", output)
        if model_match:
            facts["model"] = model_match.group(1)

        # Serial
        serial_match = re.search(r"Processor board ID\s+(\S+)", output)
        if serial_match:
            facts["serial"] = serial_match.group(1)

        return facts

    def get_inventory_summary(self) -> Dict[str, Any]:
        """
        Get summary of current inventory.

        Returns:
            Dict with inventory statistics
        """
        inventory = self._load_inventory()

        by_type = {}
        for name, device in inventory.items():
            device_type = device.get("device_type", "unknown")
            if device_type not in by_type:
                by_type[device_type] = []
            by_type[device_type].append(name)

        return {
            "total_devices": len(inventory),
            "by_type": {
                dtype: {
                    "count": len(devices),
                    "devices": devices,
                }
                for dtype, devices in by_type.items()
            },
            "nornir_available": self.nornir_available,
            "nornir_enabled": is_enabled("use_nornir"),
        }


# Singleton instance
_nornir_manager = None


def get_nornir(max_workers: int = 10) -> NornirManager:
    """Get singleton NornirManager instance"""
    global _nornir_manager
    if _nornir_manager is None:
        _nornir_manager = NornirManager(max_workers=max_workers)
    return _nornir_manager


def run_on_devices(
    command: str,
    devices: Optional[List[str]] = None,
    filter_type: Optional[str] = None,
) -> AggregatedResult:
    """
    Convenience function to run command on devices.

    Args:
        command: Command to execute
        devices: List of device names (optional)
        filter_type: Filter by device_type (optional)

    Returns:
        AggregatedResult
    """
    manager = get_nornir()
    return manager.run_command(command, devices=devices, filter_type=filter_type)
