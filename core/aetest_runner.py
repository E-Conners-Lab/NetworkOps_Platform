"""
pyATS aetest Integration for Network Testing

Provides structured network testing using pyATS aetest framework with:
- Base test classes for common network validations
- Integration with metrics collection
- Test runner with reporting
- Feature flag control

Usage:
    from core.aetest_runner import NetworkTestRunner, run_test_suite

    # Run all tests on a device
    results = run_test_suite("R1", ["connectivity", "ospf", "bgp"])

    # Run with custom parameters
    runner = NetworkTestRunner()
    results = runner.run("R1", tests=["interface_health"])
"""

import sys
import json
import logging
from datetime import datetime

from core.timestamps import now
from pathlib import Path
from typing import Dict, Any, List, Optional, Callable
from dataclasses import dataclass, field
from enum import Enum
from contextlib import contextmanager

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

# pyATS imports - optional, gracefully degrade if not installed
try:
    from pyats import aetest
    from pyats.topology import loader as topology_loader
    from genie.testbed import load as load_testbed
    PYATS_AVAILABLE = True
except ImportError:
    PYATS_AVAILABLE = False
    aetest = None

from config.devices import DEVICES, USERNAME, PASSWORD
from core.feature_flags import is_enabled
from core.metrics import test_metrics, TestOutcome, correlation

logger = logging.getLogger(__name__)


class TestStatus(Enum):
    """Test execution status"""
    PASSED = "passed"
    FAILED = "failed"
    ERRORED = "errored"
    SKIPPED = "skipped"
    BLOCKED = "blocked"


@dataclass
class TestStep:
    """Individual test step result"""
    name: str
    status: TestStatus
    duration_ms: float
    message: str = ""
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class TestCaseResult:
    """Result of a single test case"""
    name: str
    status: TestStatus
    steps: List[TestStep] = field(default_factory=list)
    duration_ms: float = 0.0
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "status": self.status.value,
            "steps": [
                {
                    "name": s.name,
                    "status": s.status.value,
                    "duration_ms": s.duration_ms,
                    "message": s.message,
                    "details": s.details
                }
                for s in self.steps
            ],
            "duration_ms": self.duration_ms,
            "error": self.error
        }


@dataclass
class TestSuiteResult:
    """Result of a complete test suite run"""
    device: str
    suite_name: str
    status: TestStatus
    test_cases: List[TestCaseResult] = field(default_factory=list)
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    correlation_id: Optional[str] = None

    @property
    def duration_ms(self) -> float:
        if self.start_time and self.end_time:
            return (self.end_time - self.start_time).total_seconds() * 1000
        return 0.0

    @property
    def passed_count(self) -> int:
        return sum(1 for tc in self.test_cases if tc.status == TestStatus.PASSED)

    @property
    def failed_count(self) -> int:
        return sum(1 for tc in self.test_cases if tc.status == TestStatus.FAILED)

    @property
    def pass_rate(self) -> float:
        total = len(self.test_cases)
        if total == 0:
            return 0.0
        return (self.passed_count / total) * 100

    def to_dict(self) -> Dict[str, Any]:
        return {
            "device": self.device,
            "suite_name": self.suite_name,
            "status": self.status.value,
            "correlation_id": self.correlation_id,
            "start_time": self.start_time.isoformat() if self.start_time else None,
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "duration_ms": self.duration_ms,
            "summary": {
                "total": len(self.test_cases),
                "passed": self.passed_count,
                "failed": self.failed_count,
                "pass_rate": f"{self.pass_rate:.1f}%"
            },
            "test_cases": [tc.to_dict() for tc in self.test_cases]
        }


class NetworkTestCase:
    """
    Base class for network test cases.

    Provides common functionality for network device testing without
    requiring full pyATS aetest infrastructure.
    """

    def __init__(self, device_name: str, device_conn=None):
        self.device_name = device_name
        self.device = device_conn
        self.steps: List[TestStep] = []
        self._start_time: Optional[datetime] = None

    @contextmanager
    def step(self, name: str):
        """Context manager for test steps with timing"""
        step_start = now()
        step_result = TestStep(
            name=name,
            status=TestStatus.PASSED,
            duration_ms=0.0
        )

        try:
            yield step_result
        except AssertionError as e:
            step_result.status = TestStatus.FAILED
            step_result.message = str(e)
            raise
        except Exception as e:
            step_result.status = TestStatus.ERRORED
            step_result.message = str(e)
            raise
        finally:
            step_end = now()
            step_result.duration_ms = (step_end - step_start).total_seconds() * 1000
            self.steps.append(step_result)

    def setup(self) -> bool:
        """Setup method - override in subclass"""
        return True

    def test(self) -> bool:
        """Main test method - override in subclass"""
        raise NotImplementedError("Subclass must implement test()")

    def cleanup(self) -> None:
        """Cleanup method - override in subclass"""
        pass

    def run(self) -> TestCaseResult:
        """Execute the test case"""
        self._start_time = now()
        result = TestCaseResult(
            name=self.__class__.__name__,
            status=TestStatus.PASSED
        )

        try:
            # Setup
            if not self.setup():
                result.status = TestStatus.BLOCKED
                result.error = "Setup failed"
                return result

            # Run test
            try:
                passed = self.test()
                if not passed:
                    result.status = TestStatus.FAILED
            except AssertionError as e:
                result.status = TestStatus.FAILED
                result.error = str(e)
            except Exception as e:
                result.status = TestStatus.ERRORED
                result.error = str(e)

        finally:
            # Cleanup
            try:
                self.cleanup()
            except Exception as e:
                logger.warning(f"Cleanup failed for {self.__class__.__name__}: {e}")

            end_time = now()
            result.duration_ms = (end_time - self._start_time).total_seconds() * 1000
            result.steps = self.steps

        return result


# =============================================================================
# Built-in Test Cases
# =============================================================================

class ConnectivityTest(NetworkTestCase):
    """Test basic device connectivity"""

    def test(self) -> bool:
        with self.step("Check device reachable"):
            if self.device is None:
                raise AssertionError(f"No connection to {self.device_name}")

        with self.step("Execute show version"):
            output = self.device.execute("show version")
            if "Cisco" not in output and "cisco" not in output:
                raise AssertionError("Unexpected show version output")

        return True


class InterfaceHealthTest(NetworkTestCase):
    """Test interface status and error rates"""

    def __init__(self, device_name: str, device_conn=None,
                 error_threshold: int = 100, expected_up: List[str] = None):
        super().__init__(device_name, device_conn)
        self.error_threshold = error_threshold
        self.expected_up = expected_up or []

    def test(self) -> bool:
        with self.step("Get interface status"):
            output = self.device.execute("show ip interface brief")
            if not output:
                raise AssertionError("No interface output received")

        with self.step("Check expected interfaces are up"):
            for intf in self.expected_up:
                if intf not in output:
                    raise AssertionError(f"Interface {intf} not found")
                # Simple check - would use parser in production
                lines = [l for l in output.split('\n') if intf in l]
                if lines and 'up' not in lines[0].lower():
                    raise AssertionError(f"Interface {intf} is not up")

        with self.step("Check for interface errors"):
            error_output = self.device.execute("show interfaces | include errors")
            # Parse error counts - simplified
            import re
            errors = re.findall(r'(\d+) input errors', error_output)
            total_errors = sum(int(e) for e in errors)
            if total_errors > self.error_threshold:
                raise AssertionError(
                    f"Total input errors ({total_errors}) exceeds threshold ({self.error_threshold})"
                )

        return True


class OSPFNeighborTest(NetworkTestCase):
    """Test OSPF neighbor adjacencies"""

    def __init__(self, device_name: str, device_conn=None,
                 min_neighbors: int = 1, expected_neighbors: List[str] = None):
        super().__init__(device_name, device_conn)
        self.min_neighbors = min_neighbors
        self.expected_neighbors = expected_neighbors or []

    def test(self) -> bool:
        with self.step("Get OSPF neighbors"):
            output = self.device.execute("show ip ospf neighbor")
            if "OSPF not enabled" in output:
                raise AssertionError("OSPF is not enabled on this device")

        with self.step(f"Verify minimum {self.min_neighbors} neighbors"):
            # Count FULL adjacencies
            full_count = output.lower().count('full')
            if full_count < self.min_neighbors:
                raise AssertionError(
                    f"Only {full_count} FULL neighbors, expected at least {self.min_neighbors}"
                )

        with self.step("Check expected neighbor IDs"):
            for neighbor_id in self.expected_neighbors:
                if neighbor_id not in output:
                    raise AssertionError(f"Expected neighbor {neighbor_id} not found")

        return True


class BGPSessionTest(NetworkTestCase):
    """Test BGP session status"""

    def __init__(self, device_name: str, device_conn=None,
                 min_established: int = 1, expected_peers: List[str] = None):
        super().__init__(device_name, device_conn)
        self.min_established = min_established
        self.expected_peers = expected_peers or []

    def test(self) -> bool:
        with self.step("Get BGP summary"):
            output = self.device.execute("show ip bgp summary")
            if "BGP not active" in output or "% BGP" in output:
                raise AssertionError("BGP is not configured on this device")

        with self.step(f"Verify minimum {self.min_established} established sessions"):
            # Count established sessions (state shows as number of prefixes)
            import re
            # Lines with numeric state are established
            established = len(re.findall(r'\d+\.\d+\.\d+\.\d+\s+\d+\s+\d+\s+\d+\s+\d+\s+\d+\s+\d+\s+\d+\s+\S+\s+\d+', output))
            if established < self.min_established:
                raise AssertionError(
                    f"Only {established} established BGP sessions, expected at least {self.min_established}"
                )

        with self.step("Check expected peer addresses"):
            for peer in self.expected_peers:
                if peer not in output:
                    raise AssertionError(f"Expected BGP peer {peer} not found")

        return True


class RoutingTableTest(NetworkTestCase):
    """Test routing table for expected routes"""

    def __init__(self, device_name: str, device_conn=None,
                 expected_routes: List[str] = None, protocol: str = None):
        super().__init__(device_name, device_conn)
        self.expected_routes = expected_routes or []
        self.protocol = protocol  # ospf, bgp, eigrp, static, connected

    def test(self) -> bool:
        with self.step("Get routing table"):
            if self.protocol:
                output = self.device.execute(f"show ip route {self.protocol}")
            else:
                output = self.device.execute("show ip route")

            if not output or "Routing Table" not in output and "Gateway" not in output:
                raise AssertionError("Could not retrieve routing table")

        with self.step("Verify expected routes present"):
            missing = []
            for route in self.expected_routes:
                if route not in output:
                    missing.append(route)

            if missing:
                raise AssertionError(f"Missing routes: {', '.join(missing)}")

        return True


class EIGRPNeighborTest(NetworkTestCase):
    """Test EIGRP neighbor adjacencies"""

    def __init__(self, device_name: str, device_conn=None,
                 min_neighbors: int = 1, expected_neighbors: List[str] = None,
                 as_number: int = None):
        super().__init__(device_name, device_conn)
        self.min_neighbors = min_neighbors
        self.expected_neighbors = expected_neighbors or []
        self.as_number = as_number

    def test(self) -> bool:
        with self.step("Get EIGRP neighbors"):
            if self.as_number:
                output = self.device.execute(f"show ip eigrp neighbors {self.as_number}")
            else:
                output = self.device.execute("show ip eigrp neighbors")

            if "EIGRP" not in output and "eigrp" not in output.lower():
                # Try named mode
                output = self.device.execute("show eigrp address-family ipv4 neighbors")

            if "not running" in output.lower() or "not enabled" in output.lower():
                raise AssertionError("EIGRP is not enabled on this device")

        with self.step(f"Verify minimum {self.min_neighbors} neighbors"):
            # Count neighbor entries (lines with IP addresses)
            import re
            neighbor_lines = re.findall(r'\d+\.\d+\.\d+\.\d+', output)
            neighbor_count = len(neighbor_lines)
            if neighbor_count < self.min_neighbors:
                raise AssertionError(
                    f"Only {neighbor_count} EIGRP neighbors, expected at least {self.min_neighbors}"
                )

        with self.step("Check expected neighbor addresses"):
            for neighbor in self.expected_neighbors:
                if neighbor not in output:
                    raise AssertionError(f"Expected EIGRP neighbor {neighbor} not found")

        with self.step("Check neighbor uptime/stability"):
            # Look for stuck-in-active or other issues
            if "SIA" in output or "stuck" in output.lower():
                raise AssertionError("EIGRP has stuck-in-active (SIA) issues")

        return True


class DMVPNTunnelTest(NetworkTestCase):
    """Test DMVPN tunnel status"""

    def __init__(self, device_name: str, device_conn=None,
                 tunnel_interface: str = "Tunnel100", min_spokes: int = 0):
        super().__init__(device_name, device_conn)
        self.tunnel_interface = tunnel_interface
        self.min_spokes = min_spokes

    def test(self) -> bool:
        with self.step(f"Check {self.tunnel_interface} status"):
            output = self.device.execute(f"show interface {self.tunnel_interface}")
            if "up" not in output.lower() or "line protocol is up" not in output.lower():
                raise AssertionError(f"{self.tunnel_interface} is not up/up")

        with self.step("Check NHRP mappings"):
            nhrp_output = self.device.execute("show ip nhrp")
            if "NHRP" not in nhrp_output and "nhrp" not in nhrp_output.lower():
                if self.min_spokes > 0:
                    raise AssertionError("No NHRP mappings found")

        with self.step(f"Verify minimum {self.min_spokes} NHRP entries"):
            if self.min_spokes > 0:
                # Count NHRP entries
                entry_count = nhrp_output.lower().count('via ')
                if entry_count < self.min_spokes:
                    raise AssertionError(
                        f"Only {entry_count} NHRP entries, expected at least {self.min_spokes}"
                    )

        return True


# =============================================================================
# Test Registry
# =============================================================================

# Map test names to test classes
TEST_REGISTRY: Dict[str, type] = {
    "connectivity": ConnectivityTest,
    "interface_health": InterfaceHealthTest,
    "ospf": OSPFNeighborTest,
    "eigrp": EIGRPNeighborTest,
    "bgp": BGPSessionTest,
    "routing": RoutingTableTest,
    "dmvpn": DMVPNTunnelTest,
}


def get_available_tests() -> List[str]:
    """Get list of available test names"""
    return list(TEST_REGISTRY.keys())


# =============================================================================
# Test Runner
# =============================================================================

class NetworkTestRunner:
    """
    Executes network test suites with metrics integration.

    Features:
    - Runs multiple test cases per device
    - Integrates with correlation ID tracking
    - Records results to test metrics
    - Supports parallel device testing
    """

    def __init__(self):
        self.testbed = None

    def _get_testbed(self):
        """Create pyATS testbed from device inventory"""
        if not PYATS_AVAILABLE:
            return None

        testbed_dict = {
            "testbed": {
                "name": "network_lab",
                "credentials": {
                    "default": {
                        "username": USERNAME,
                        "password": PASSWORD,
                    }
                }
            },
            "devices": {}
        }

        for name, device in DEVICES.items():
            device_type = device.get("device_type", "")
            if device_type == "cisco_xe":
                dev_type = "switch" if "Switch" in name else "router"
                testbed_dict["devices"][name] = {
                    "os": "iosxe",
                    "type": dev_type,
                    "connections": {
                        "cli": {
                            "protocol": "ssh",
                            "ip": device["host"],
                            "port": 22,
                        }
                    },
                    "credentials": {
                        "default": {
                            "username": USERNAME,
                            "password": PASSWORD,
                        }
                    }
                }

        return load_testbed(testbed_dict)

    def run(
        self,
        device_name: str,
        tests: List[str] = None,
        test_params: Dict[str, Dict[str, Any]] = None
    ) -> TestSuiteResult:
        """
        Run test suite on a device.

        Args:
            device_name: Device to test
            tests: List of test names to run (default: all)
            test_params: Parameters for each test {test_name: {param: value}}

        Returns:
            TestSuiteResult with all test case results
        """
        # Check feature flag
        if not is_enabled("use_aetest"):
            return TestSuiteResult(
                device=device_name,
                suite_name="disabled",
                status=TestStatus.SKIPPED,
                test_cases=[TestCaseResult(
                    name="aetest_disabled",
                    status=TestStatus.SKIPPED,
                    error="aetest integration is disabled via feature flag"
                )]
            )

        # Validate device
        if device_name not in DEVICES:
            return TestSuiteResult(
                device=device_name,
                suite_name="error",
                status=TestStatus.ERRORED,
                test_cases=[TestCaseResult(
                    name="device_not_found",
                    status=TestStatus.ERRORED,
                    error=f"Device '{device_name}' not found"
                )]
            )

        # Determine tests to run
        if tests is None:
            tests = get_available_tests()

        test_params = test_params or {}

        # Start suite
        with correlation.context() as run_id:
            result = TestSuiteResult(
                device=device_name,
                suite_name=f"network_tests_{device_name}",
                status=TestStatus.PASSED,
                start_time=now(),
                correlation_id=run_id
            )

            # Connect to device
            device_conn = None
            try:
                if PYATS_AVAILABLE:
                    testbed = self._get_testbed()
                    if testbed and device_name in testbed.devices:
                        device_conn = testbed.devices[device_name]
                        device_conn.connect(log_stdout=False)
            except Exception as e:
                logger.warning(f"Could not connect to {device_name}: {e}")

            # Run each test
            for test_name in tests:
                if test_name not in TEST_REGISTRY:
                    result.test_cases.append(TestCaseResult(
                        name=test_name,
                        status=TestStatus.ERRORED,
                        error=f"Unknown test: {test_name}"
                    ))
                    continue

                # Create test instance with parameters
                test_class = TEST_REGISTRY[test_name]
                params = test_params.get(test_name, {})

                try:
                    test_instance = test_class(device_name, device_conn, **params)
                    test_result = test_instance.run()
                    result.test_cases.append(test_result)

                    # Record to metrics
                    outcome = (
                        TestOutcome.PASSED if test_result.status == TestStatus.PASSED
                        else TestOutcome.FAILED if test_result.status == TestStatus.FAILED
                        else TestOutcome.ERROR
                    )
                    test_metrics.record_run(
                        outcome=outcome,
                        duration_ms=test_result.duration_ms,
                        test_name=f"{device_name}.{test_name}"
                    )

                except Exception as e:
                    result.test_cases.append(TestCaseResult(
                        name=test_name,
                        status=TestStatus.ERRORED,
                        error=str(e)
                    ))
                    test_metrics.record_run(
                        outcome=TestOutcome.ERROR,
                        duration_ms=0,
                        test_name=f"{device_name}.{test_name}"
                    )

            # Disconnect
            if device_conn:
                try:
                    device_conn.disconnect()
                except Exception:
                    pass

            # Determine overall status
            result.end_time = now()

            if any(tc.status == TestStatus.ERRORED for tc in result.test_cases):
                result.status = TestStatus.ERRORED
            elif any(tc.status == TestStatus.FAILED for tc in result.test_cases):
                result.status = TestStatus.FAILED
            elif all(tc.status == TestStatus.PASSED for tc in result.test_cases):
                result.status = TestStatus.PASSED
            else:
                result.status = TestStatus.PASSED  # Mix of passed/skipped

        return result


def run_test_suite(
    device_name: str,
    tests: List[str] = None,
    test_params: Dict[str, Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Convenience function to run tests and return dict result.

    Args:
        device_name: Device to test
        tests: List of test names
        test_params: Test parameters

    Returns:
        Dictionary with test results
    """
    runner = NetworkTestRunner()
    result = runner.run(device_name, tests, test_params)
    return result.to_dict()


def run_tests_on_devices(
    devices: List[str],
    tests: List[str] = None,
    test_params: Dict[str, Dict[str, Any]] = None,
    max_workers: int = 4
) -> Dict[str, Any]:
    """
    Run tests on multiple devices in parallel.

    Args:
        devices: List of device names
        tests: List of test names
        test_params: Test parameters
        max_workers: Maximum parallel device connections (default: 4)

    Returns:
        Dictionary with aggregated results
    """
    from concurrent.futures import ThreadPoolExecutor, as_completed

    start_time = now()
    results = {
        "timestamp": start_time.isoformat(),
        "devices_tested": len(devices),
        "results": {},
        "summary": {
            "passed": 0,
            "failed": 0,
            "errored": 0,
            "total_tests": 0
        }
    }

    def run_device_tests(device_name: str) -> tuple:
        """Run tests on a single device (for parallel execution)"""
        runner = NetworkTestRunner()
        result = runner.run(device_name, tests, test_params)
        return device_name, result

    # Run tests in parallel
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(run_device_tests, device): device
            for device in devices
        }

        for future in as_completed(futures):
            device_name, result = future.result()
            results["results"][device_name] = result.to_dict()

            # Update summary
            results["summary"]["total_tests"] += len(result.test_cases)
            results["summary"]["passed"] += result.passed_count
            results["summary"]["failed"] += result.failed_count
            if result.status == TestStatus.ERRORED:
                results["summary"]["errored"] += 1

    # Add timing info
    end_time = now()
    results["duration_ms"] = (end_time - start_time).total_seconds() * 1000
    results["parallel_workers"] = min(max_workers, len(devices))

    return results


# =============================================================================
# MCP Tool Registration
# =============================================================================

def register_aetest_tools(mcp):
    """Register aetest tools with MCP server"""

    @mcp.tool()
    def aetest_run_tests(device_name: str, tests: str = "") -> str:
        """
        Run network tests on a device.

        Args:
            device_name: Device to test (e.g., "R1")
            tests: Comma-separated test names, or empty for all
                   Available: connectivity, interface_health, ospf, bgp, routing, dmvpn

        Returns:
            JSON with test results including pass/fail status and details
        """
        test_list = [t.strip() for t in tests.split(",")] if tests else None
        result = run_test_suite(device_name, test_list)
        return json.dumps(result, indent=2)

    @mcp.tool()
    def aetest_list_tests() -> str:
        """
        List available network tests.

        Returns:
            JSON with available test names and descriptions
        """
        tests = []
        for name, cls in TEST_REGISTRY.items():
            tests.append({
                "name": name,
                "class": cls.__name__,
                "description": cls.__doc__.strip() if cls.__doc__ else ""
            })

        return json.dumps({
            "status": "success",
            "tests": tests,
            "feature_enabled": is_enabled("use_aetest")
        }, indent=2)

    @mcp.tool()
    def aetest_run_suite(devices: str, tests: str = "") -> str:
        """
        Run tests on multiple devices.

        Args:
            devices: Comma-separated device names (e.g., "R1,R2,R3")
            tests: Comma-separated test names, or empty for all

        Returns:
            JSON with aggregated test results for all devices
        """
        device_list = [d.strip() for d in devices.split(",")]
        test_list = [t.strip() for t in tests.split(",")] if tests else None
        result = run_tests_on_devices(device_list, test_list)
        return json.dumps(result, indent=2)


if __name__ == "__main__":
    # Quick test
    print("Available tests:", get_available_tests())
    print("\nRunning connectivity test on R1...")
    result = run_test_suite("R1", ["connectivity"])
    print(json.dumps(result, indent=2))
