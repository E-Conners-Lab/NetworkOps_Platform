"""
Testing MCP tools.

This module provides tools for pyATS and aetest operations:
- pyats_generate_testbed: Generate testbed YAML from inventory
- pyats_learn_feature: Learn device feature state
- pyats_snapshot_state: Capture baseline state
- pyats_diff_state: Compare against baseline
- pyats_list_baselines: List saved baselines
- pyats_list_templates: List golden templates
- pyats_cve_check: CVE vulnerability check
- pyats_interface_report: Interface utilization report
- pyats_inventory_report: Hardware/software inventory
- aetest_run_tests: Run network tests on a device
- aetest_list_tests: List available tests
- aetest_run_suite: Run tests on multiple devices

Note: pyats_check_compliance and pyats_security_audit removed - use compliance_check() instead.
"""

import asyncio
import json

# Import pyATS tools (optional - gracefully handle if pyats not installed)
try:
    from scripts.pyats_tools import (
        generate_testbed,
        learn_feature,
        snapshot_state,
        diff_state,
        list_baselines,
        list_templates,
        cve_check,
        interface_report,
        inventory_report,
    )
    PYATS_AVAILABLE = True
except ImportError:
    PYATS_AVAILABLE = False


# =============================================================================
# pyATS MCP Tool Functions
# =============================================================================

async def pyats_generate_testbed() -> str:
    """Generate pyATS testbed YAML from device inventory"""
    if not PYATS_AVAILABLE:
        return json.dumps({"error": "pyATS not installed. Run: pip install pyats[full]"})
    return await asyncio.to_thread(generate_testbed)


async def pyats_learn_feature(device_name: str, feature: str) -> str:
    """Learn device feature state (ospf, eigrp, interface, routing, bgp, vrf, arp, platform)"""
    if not PYATS_AVAILABLE:
        return json.dumps({"error": "pyATS not installed. Run: pip install pyats[full]"})
    return await asyncio.to_thread(learn_feature, device_name, feature)


async def pyats_snapshot_state(device_name: str, label: str = "baseline") -> str:
    """Capture device state to baseline file for later comparison"""
    if not PYATS_AVAILABLE:
        return json.dumps({"error": "pyATS not installed. Run: pip install pyats[full]"})
    return await asyncio.to_thread(snapshot_state, device_name, label)


async def pyats_diff_state(device_name: str, label: str = "baseline") -> str:
    """Compare current device state against saved baseline"""
    if not PYATS_AVAILABLE:
        return json.dumps({"error": "pyATS not installed. Run: pip install pyats[full]"})
    return await asyncio.to_thread(diff_state, device_name, label)


async def pyats_list_baselines() -> str:
    """List all saved baseline snapshots"""
    if not PYATS_AVAILABLE:
        return json.dumps({"error": "pyATS not installed. Run: pip install pyats[full]"})
    return await asyncio.to_thread(list_baselines)


async def pyats_list_templates() -> str:
    """List available golden config templates"""
    if not PYATS_AVAILABLE:
        return json.dumps({"error": "pyATS not installed. Run: pip install pyats[full]"})
    return await asyncio.to_thread(list_templates)


async def pyats_cve_check(device_name: str = None) -> str:
    """
    Check device software versions against known CVE database.

    Cross-references IOS-XE version with known vulnerabilities and
    provides risk assessment and upgrade recommendations.

    Args:
        device_name: Specific device to check, or None for all Cisco devices
    """
    if not PYATS_AVAILABLE:
        return json.dumps({"error": "pyATS not installed. Run: pip install pyats[full]"})
    return await asyncio.to_thread(cve_check, device_name)


async def pyats_interface_report(device_name: str = None, top_n: int = 10) -> str:
    """
    Generate interface utilization and error report.

    Uses pyATS to learn interface state including bandwidth, traffic counters,
    and error rates. Returns top interfaces by traffic and interfaces with errors.

    Args:
        device_name: Specific device, or None for all Cisco devices
        top_n: Number of top interfaces to return per device (default: 10)
    """
    if not PYATS_AVAILABLE:
        return json.dumps({"error": "pyATS not installed. Run: pip install pyats[full]"})
    return await asyncio.to_thread(interface_report, device_name, top_n)


async def pyats_inventory_report(device_name: str = None) -> str:
    """
    Generate fleet-wide hardware and software inventory report.

    Uses pyATS to collect software version, hardware model, serial numbers,
    uptime, and module information across devices.

    Args:
        device_name: Specific device, or None for all Cisco devices
    """
    if not PYATS_AVAILABLE:
        return json.dumps({"error": "pyATS not installed. Run: pip install pyats[full]"})
    return await asyncio.to_thread(inventory_report, device_name)


# =============================================================================
# aetest MCP Tool Functions
# =============================================================================

async def aetest_run_tests(device_name: str, tests: str = "") -> str:
    """
    Run network tests on a device using aetest framework.

    Args:
        device_name: Device to test (e.g., "R1")
        tests: Comma-separated test names, or empty for all
               Available: connectivity, interface_health, ospf, eigrp, bgp, routing, dmvpn

    Returns:
        JSON with test results including pass/fail status and details

    Examples:
        aetest_run_tests("R1")  # Run all tests
        aetest_run_tests("R1", "ospf,eigrp")  # Run specific tests
    """
    from core.aetest_runner import run_test_suite
    test_list = [t.strip() for t in tests.split(",")] if tests else None
    result = await asyncio.to_thread(run_test_suite, device_name, test_list)
    return json.dumps(result, indent=2)


async def aetest_list_tests() -> str:
    """
    List available network tests.

    Returns:
        JSON with available test names and descriptions
    """
    from core.aetest_runner import TEST_REGISTRY, get_available_tests
    from core.feature_flags import is_enabled

    tests = []
    for name in get_available_tests():
        cls = TEST_REGISTRY[name]
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


async def aetest_run_suite(devices: str, tests: str = "") -> str:
    """
    Run tests on multiple devices.

    Args:
        devices: Comma-separated device names (e.g., "R1,R2,R3,R4")
        tests: Comma-separated test names, or empty for all

    Returns:
        JSON with aggregated test results for all devices

    Examples:
        aetest_run_suite("R1,R2,R3,R4", "ospf,eigrp")  # OSPF/EIGRP on all routers
        aetest_run_suite("R1,R2", "connectivity")  # Connectivity check
    """
    from core.aetest_runner import run_tests_on_devices
    device_list = [d.strip() for d in devices.split(",")]
    test_list = [t.strip() for t in tests.split(",")] if tests else None
    result = await asyncio.to_thread(run_tests_on_devices, device_list, test_list)
    return json.dumps(result, indent=2)


# =============================================================================
# Tool Registry
# =============================================================================

TOOLS = [
    # pyATS tools (9) - pyats_check_compliance and pyats_security_audit removed (use compliance_check instead)
    {"fn": pyats_generate_testbed, "name": "pyats_generate_testbed", "category": "testing"},
    {"fn": pyats_learn_feature, "name": "pyats_learn_feature", "category": "testing"},
    {"fn": pyats_snapshot_state, "name": "pyats_snapshot_state", "category": "testing"},
    {"fn": pyats_diff_state, "name": "pyats_diff_state", "category": "testing"},
    {"fn": pyats_list_baselines, "name": "pyats_list_baselines", "category": "testing"},
    {"fn": pyats_list_templates, "name": "pyats_list_templates", "category": "testing"},
    {"fn": pyats_cve_check, "name": "pyats_cve_check", "category": "testing"},
    {"fn": pyats_interface_report, "name": "pyats_interface_report", "category": "testing"},
    {"fn": pyats_inventory_report, "name": "pyats_inventory_report", "category": "testing"},
    # aetest tools (3)
    {"fn": aetest_run_tests, "name": "aetest_run_tests", "category": "testing"},
    {"fn": aetest_list_tests, "name": "aetest_list_tests", "category": "testing"},
    {"fn": aetest_run_suite, "name": "aetest_run_suite", "category": "testing"},
]
