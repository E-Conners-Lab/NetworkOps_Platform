#!/usr/bin/env python3
"""
Pre-Demo Validation Script

Validates all systems are ready for the NetBox Labs demo:
1. NetBox is running with lab data
2. All network devices are reachable
3. Containerlab VM is running
4. MCP server tools work
5. Key demo scenarios are functional

Usage:
    python scripts/pre_demo_check.py
    python scripts/pre_demo_check.py --fix  # Attempt to fix issues
"""

import argparse
import asyncio
import json
import os
import subprocess
import sys
import time
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))


class Status(Enum):
    PASS = "✅"
    FAIL = "❌"
    WARN = "⚠️"
    SKIP = "⏭️"


@dataclass
class CheckResult:
    name: str
    status: Status
    message: str
    fix_hint: str = ""


def print_header(title: str) -> None:
    """Print a section header."""
    print(f"\n{'='*60}")
    print(f"  {title}")
    print(f"{'='*60}")


def print_result(result: CheckResult) -> None:
    """Print a check result."""
    print(f"{result.status.value} {result.name}: {result.message}")
    if result.status == Status.FAIL and result.fix_hint:
        print(f"   └─ Fix: {result.fix_hint}")


def run_cmd(cmd: str, timeout: int = 30) -> tuple[int, str, str]:
    """Run a shell command and return (returncode, stdout, stderr)."""
    try:
        result = subprocess.run(
            cmd,
            shell=True,  # nosec B602 - commands are hardcoded, not from user input
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "Command timed out"
    except Exception as e:
        return -1, "", str(e)


# =============================================================================
# NetBox Checks
# =============================================================================

def check_netbox_running() -> CheckResult:
    """Check if NetBox container is running."""
    # Check for main netbox container (may be named 'netbox' or 'netbox-netbox')
    code, out, _ = run_cmd("docker ps --filter 'name=^netbox$' --format '{{.Status}}'")
    if code == 0 and "Up" in out:
        return CheckResult("NetBox Container", Status.PASS, "Running")
    # Fallback: check with different naming
    code, out, _ = run_cmd("docker ps --filter 'name=netbox' --format '{{.Names}}' | head -1")
    if code == 0 and "netbox" in out.lower():
        return CheckResult("NetBox Container", Status.PASS, "Running")
    return CheckResult(
        "NetBox Container",
        Status.FAIL,
        "Not running",
        "cd netbox && docker compose up -d",
    )


def check_netbox_api() -> CheckResult:
    """Check NetBox API is responding."""
    code, out, _ = run_cmd("curl -s -o /dev/null -w '%{http_code}' http://localhost:8000/api/")
    if code == 0 and out.strip() in ("200", "403"):  # 403 is ok, means API is up but needs auth
        return CheckResult("NetBox API", Status.PASS, "Responding")
    return CheckResult(
        "NetBox API",
        Status.FAIL,
        "Not responding",
        "Wait 2 min after starting, or check: docker compose logs netbox",
    )


def check_netbox_devices() -> CheckResult:
    """Check NetBox has devices populated."""
    try:
        from config.netbox_client import get_client, NETBOX_API_TOKEN

        if not NETBOX_API_TOKEN:
            return CheckResult(
                "NetBox Devices",
                Status.WARN,
                "No API token configured",
                "Set NETBOX_API_TOKEN in .env",
            )

        client = get_client()
        devices = client.get_devices()
        count = len(devices)

        if count >= 10:
            return CheckResult("NetBox Devices", Status.PASS, f"{count} devices found")
        elif count > 0:
            return CheckResult(
                "NetBox Devices",
                Status.WARN,
                f"Only {count} devices (expected 13)",
                "python scripts/populate_netbox.py",
            )
        else:
            return CheckResult(
                "NetBox Devices",
                Status.FAIL,
                "No devices found",
                "python scripts/populate_netbox.py",
            )
    except Exception as e:
        return CheckResult("NetBox Devices", Status.FAIL, str(e)[:50])


# =============================================================================
# Device Reachability Checks
# =============================================================================

def check_eve_ng_reachable() -> CheckResult:
    """Check EVE-NG is reachable."""
    eve_ng_host = os.getenv("EVE_NG_HOST", "203.0.113.201")
    code, _, _ = run_cmd(f"ping -c 1 -W 2 {eve_ng_host}")
    if code == 0:
        return CheckResult("EVE-NG Host", Status.PASS, f"Reachable ({eve_ng_host})")
    return CheckResult(
        "EVE-NG Host",
        Status.FAIL,
        "Not reachable",
        "Check EVE-NG is running and network route exists",
    )


def check_lab_network_route() -> CheckResult:
    """Check route to lab network exists."""
    code, out, _ = run_cmd("netstat -rn | grep 10.255.255")
    if code == 0 and "10.255.255" in out:
        return CheckResult("Lab Network Route", Status.PASS, "10.255.255.0/24 via EVE-NG")
    return CheckResult(
        "Lab Network Route",
        Status.FAIL,
        "No route to 10.255.255.0/24",
        f"sudo route -n add -net 10.255.255.0/24 {os.getenv('EVE_NG_HOST', '203.0.113.201')}",
    )


async def check_device_health() -> list[CheckResult]:
    """Check all devices via MCP health_check_all."""
    results = []

    try:
        from network_mcp_async import health_check_all

        health_json = await health_check_all(use_netconf=False)
        health = json.loads(health_json) if isinstance(health_json, str) else health_json

        # Parse results - structure is {mode, elapsed_seconds, summary, devices: [...]}
        summary = health.get("summary", {})
        devices = health.get("devices", [])

        healthy = summary.get("healthy", 0)
        degraded = summary.get("degraded", 0)
        critical = summary.get("critical", 0)

        # Find unhealthy device names
        unhealthy = [
            d.get("device", "unknown")
            for d in devices
            if d.get("status") != "healthy"
        ]

        total = len(devices)
        if critical == 0 and degraded == 0:
            results.append(CheckResult(
                "Device Health",
                Status.PASS,
                f"All {healthy} devices healthy",
            ))
        elif critical == 0:
            results.append(CheckResult(
                "Device Health",
                Status.WARN,
                f"{healthy}/{total} healthy, {degraded} degraded",
                "Check degraded devices in EVE-NG",
            ))
        else:
            results.append(CheckResult(
                "Device Health",
                Status.FAIL,
                f"{healthy}/{total} healthy, {critical} critical: {', '.join(unhealthy[:5])}",
                "Check device power/connectivity in EVE-NG",
            ))
    except Exception as e:
        results.append(CheckResult(
            "Device Health",
            Status.FAIL,
            f"Health check failed: {str(e)[:40]}",
        ))

    return results


# =============================================================================
# Containerlab Checks
# =============================================================================

def check_multipass_vm() -> CheckResult:
    """Check Multipass Containerlab VM is running."""
    code, out, _ = run_cmd("multipass list | grep containerlab")
    if code == 0 and "Running" in out:
        return CheckResult("Containerlab VM", Status.PASS, "Running")
    elif code == 0 and "Stopped" in out:
        return CheckResult(
            "Containerlab VM",
            Status.FAIL,
            "Stopped",
            "multipass start containerlab",
        )
    return CheckResult(
        "Containerlab VM",
        Status.FAIL,
        "Not found",
        "Check Multipass installation",
    )


def check_containerlab_topology() -> CheckResult:
    """Check Containerlab containers are running."""
    code, out, _ = run_cmd("multipass exec containerlab -- sudo docker ps --format '{{.Names}}' | grep clab")
    if code == 0:
        containers = [c.strip() for c in out.strip().split('\n') if c.strip()]
        if len(containers) >= 4:
            return CheckResult("Containerlab Topology", Status.PASS, f"{len(containers)} containers running")
        elif containers:
            return CheckResult(
                "Containerlab Topology",
                Status.WARN,
                f"Only {len(containers)} containers",
                "cd containerlab && sudo clab deploy",
            )
    return CheckResult(
        "Containerlab Topology",
        Status.FAIL,
        "No containers found",
        "multipass exec containerlab -- 'cd datacenter && sudo clab deploy'",
    )


def check_containerlab_route() -> CheckResult:
    """Check route to Containerlab network."""
    code, out, _ = run_cmd("netstat -rn | grep 172.20.20")
    if code == 0 and "172.20.20" in out:
        return CheckResult("Containerlab Route", Status.PASS, "172.20.20.0/24 via Multipass")
    return CheckResult(
        "Containerlab Route",
        Status.WARN,
        "No route (eBGP demo won't work)",
        "sudo route -n add -net 172.20.20.0/24 $(multipass info containerlab | grep IPv4 | awk '{print $2}')",
    )


# =============================================================================
# MCP & Memory Checks
# =============================================================================

async def check_mcp_tools() -> CheckResult:
    """Check MCP tools are functional."""
    try:
        from network_mcp_async import get_devices

        # get_devices is synchronous
        devices = get_devices()
        if devices:
            return CheckResult("MCP Tools", Status.PASS, f"get_devices returned {len(devices)} devices")
        return CheckResult("MCP Tools", Status.WARN, "No devices returned")
    except Exception as e:
        return CheckResult("MCP Tools", Status.FAIL, str(e)[:50])


async def check_memory_system() -> CheckResult:
    """Check MCP memory system is working."""
    try:
        from memory.store import MemoryStore
        store = MemoryStore()
        stats = await store.get_stats()
        if stats and stats.get("is_healthy"):
            return CheckResult(
                "Memory System",
                Status.PASS,
                f"{stats.get('tool_calls', 0)} calls, {stats.get('conversations', 0)} notes stored",
            )
        return CheckResult("Memory System", Status.WARN, "Database not healthy")
    except ImportError:
        return CheckResult(
            "Memory System",
            Status.FAIL,
            "Module not found",
            "Run: pip install -r requirements.txt",
        )
    except Exception as e:
        return CheckResult("Memory System", Status.FAIL, str(e)[:50])


# =============================================================================
# Demo Scenario Checks
# =============================================================================

async def check_full_network_test() -> CheckResult:
    """Run full network test to validate demo scenario."""
    try:
        from network_mcp_async import full_network_test

        result_json = await full_network_test()
        result = json.loads(result_json) if isinstance(result_json, str) else result_json

        # Structure is {ospf, bgp, dmvpn, ping, summary: {passed, failed, tests}}
        summary = result.get("summary", {})
        passed = summary.get("passed", 0)
        failed = summary.get("failed", 0)
        total = passed + failed

        if failed == 0 and passed > 0:
            return CheckResult(
                "Full Network Test",
                Status.PASS,
                f"All {passed} checks passed (OSPF/BGP/DMVPN/Ping)",
            )
        elif failed <= 2:
            return CheckResult(
                "Full Network Test",
                Status.WARN,
                f"{passed}/{total} passed, {failed} failed",
                "Check OSPF/BGP/DMVPN config on failed devices",
            )
        else:
            return CheckResult(
                "Full Network Test",
                Status.FAIL,
                f"{passed}/{total} passed, {failed} failed",
                "Multiple failures - check routing protocols",
            )
    except Exception as e:
        return CheckResult("Full Network Test", Status.FAIL, str(e)[:50])


async def check_r3_health() -> CheckResult:
    """Specifically check R3 for the demo break/fix scenario."""
    try:
        from network_mcp_async import health_check

        result = await health_check("R3")
        if "healthy" in str(result).lower():
            return CheckResult("R3 Demo Target", Status.PASS, "Healthy and ready for demo")
        return CheckResult("R3 Demo Target", Status.WARN, "May have issues")
    except Exception as e:
        return CheckResult("R3 Demo Target", Status.FAIL, str(e)[:50])


# =============================================================================
# Dashboard Check
# =============================================================================

def check_dashboard() -> CheckResult:
    """Check if dashboard API is running."""
    code, out, _ = run_cmd("curl -s -o /dev/null -w '%{http_code}' http://localhost:5001/api/devices")
    if code == 0 and out.strip() == "200":
        return CheckResult("Dashboard API", Status.PASS, "Running on :5001")
    return CheckResult(
        "Dashboard API",
        Status.SKIP,
        "Not running (optional)",
        "python dashboard/api_server.py",
    )


# =============================================================================
# Main
# =============================================================================

async def run_all_checks() -> list[CheckResult]:
    """Run all pre-demo checks."""
    all_results = []

    # NetBox
    print_header("NetBox Integration")
    netbox_checks = [
        check_netbox_running(),
        check_netbox_api(),
        check_netbox_devices(),
    ]
    for r in netbox_checks:
        print_result(r)
        all_results.append(r)

    # Network Reachability
    print_header("Network Reachability")
    network_checks = [
        check_eve_ng_reachable(),
        check_lab_network_route(),
    ]
    for r in network_checks:
        print_result(r)
        all_results.append(r)

    # Device Health (async)
    print("\n⏳ Running device health checks (this takes ~10 seconds)...")
    health_results = await check_device_health()
    for r in health_results:
        print_result(r)
        all_results.append(r)

    # Containerlab
    print_header("Containerlab (Multi-Vendor)")
    clab_checks = [
        check_multipass_vm(),
        check_containerlab_topology(),
        check_containerlab_route(),
    ]
    for r in clab_checks:
        print_result(r)
        all_results.append(r)

    # MCP & Memory
    print_header("MCP Server & Memory")
    mcp_result = await check_mcp_tools()
    print_result(mcp_result)
    all_results.append(mcp_result)

    memory_result = await check_memory_system()
    print_result(memory_result)
    all_results.append(memory_result)

    # Demo Scenarios
    print_header("Demo Scenarios")
    print("\n⏳ Running full network test...")
    fnt_result = await check_full_network_test()
    print_result(fnt_result)
    all_results.append(fnt_result)

    r3_result = await check_r3_health()
    print_result(r3_result)
    all_results.append(r3_result)

    # Dashboard (optional)
    print_header("Optional Components")
    dash_result = check_dashboard()
    print_result(dash_result)
    all_results.append(dash_result)

    return all_results


def print_summary(results: list[CheckResult]) -> bool:
    """Print summary and return True if demo-ready."""
    print_header("SUMMARY")

    passed = sum(1 for r in results if r.status == Status.PASS)
    failed = sum(1 for r in results if r.status == Status.FAIL)
    warned = sum(1 for r in results if r.status == Status.WARN)
    skipped = sum(1 for r in results if r.status == Status.SKIP)

    print(f"  ✅ Passed:  {passed}")
    print(f"  ❌ Failed:  {failed}")
    print(f"  ⚠️  Warnings: {warned}")
    print(f"  ⏭️  Skipped: {skipped}")

    if failed == 0:
        print("\n🎉 DEMO READY! All critical checks passed.")
        if warned > 0:
            print("   (Review warnings above for optimal demo)")
        return True
    else:
        print("\n🚨 NOT READY - Fix the failed checks above before demo.")
        return False


def main():
    parser = argparse.ArgumentParser(description="Pre-demo validation")
    parser.add_argument("--fix", action="store_true", help="Attempt to fix issues (not implemented)")
    args = parser.parse_args()

    print("\n" + "="*60)
    print("  🎬 PRE-DEMO VALIDATION")
    print("  NetBox Labs Demo Readiness Check")
    print("="*60)

    start = time.time()
    results = asyncio.run(run_all_checks())
    elapsed = time.time() - start

    is_ready = print_summary(results)
    print(f"\n  ⏱️  Completed in {elapsed:.1f} seconds\n")

    sys.exit(0 if is_ready else 1)


if __name__ == "__main__":
    main()
