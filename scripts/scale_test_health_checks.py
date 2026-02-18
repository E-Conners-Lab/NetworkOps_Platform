#!/usr/bin/env python3
"""
Scale Test: Simulated Health Checks for 100-5000 Devices

This test mocks SSH/NETCONF connections to stress-test the async
parallelization and semaphore throttling logic without needing real devices.

Tests:
1. Raw async throughput (no throttling)
2. Semaphore-throttled throughput (realistic)
3. Memory usage at scale
4. Optimal semaphore limit finding
5. Failure injection (% of devices fail)

Usage:
    python scripts/scale_test_health_checks.py
    python scripts/scale_test_health_checks.py --devices 1000 --concurrency 50
    python scripts/scale_test_health_checks.py --find-optimal
"""

import asyncio
import argparse
import random
import time
import tracemalloc
import json
import sys
from dataclasses import dataclass
from typing import Optional
from statistics import mean, stdev


@dataclass
class MockDevice:
    """Simulated network device"""
    name: str
    ip: str
    platform: str
    latency_ms: float  # Simulated response time
    fail_rate: float   # 0.0 to 1.0 chance of failure


@dataclass
class HealthResult:
    """Health check result"""
    device: str
    status: str  # healthy, degraded, critical
    latency_ms: float
    interfaces: int
    error: Optional[str] = None


class MockDevicePool:
    """Generate mock device inventory at scale"""

    PLATFORMS = ["cisco_xe", "cisco_nxos", "juniper_junos", "arista_eos", "linux"]

    def __init__(self, count: int, fail_rate: float = 0.0, latency_range: tuple = (50, 200)):
        self.devices = {}
        self.latency_range = latency_range

        for i in range(count):
            name = f"R{i+1:04d}"  # R0001, R0002, etc.
            self.devices[name] = MockDevice(
                name=name,
                ip=f"10.{(i // 65536) % 256}.{(i // 256) % 256}.{i % 256}",
                platform=random.choice(self.PLATFORMS),
                latency_ms=random.uniform(*latency_range),
                fail_rate=fail_rate
            )

    def get_device(self, name: str) -> MockDevice:
        return self.devices[name]

    def list_devices(self) -> list[str]:
        return list(self.devices.keys())


async def mock_health_check(device: MockDevice) -> HealthResult:
    """
    Simulates an SSH health check with realistic latency.

    This mimics what Scrapli would do:
    1. Connect to device (latency)
    2. Run 'show ip interface brief'
    3. Parse response
    4. Return structured result
    """
    # Simulate network latency + command execution
    await asyncio.sleep(device.latency_ms / 1000)

    # Simulate random failures
    if random.random() < device.fail_rate:
        return HealthResult(
            device=device.name,
            status="critical",
            latency_ms=device.latency_ms,
            interfaces=0,
            error="Connection timeout"
        )

    # Simulate successful response
    interfaces = random.randint(4, 24)
    status = "healthy" if random.random() > 0.1 else "degraded"

    return HealthResult(
        device=device.name,
        status=status,
        latency_ms=device.latency_ms,
        interfaces=interfaces
    )


async def throttled_check(device: MockDevice, semaphore: asyncio.Semaphore) -> HealthResult:
    """Execute health check with semaphore throttling"""
    async with semaphore:
        return await mock_health_check(device)


async def run_health_check_all(
    pool: MockDevicePool,
    max_concurrent: int = 20,
    use_throttling: bool = True
) -> dict:
    """
    Run health checks on all devices in parallel.

    Mirrors the real health_check_all() implementation.
    """
    start = time.perf_counter()
    device_names = pool.list_devices()

    if use_throttling:
        semaphore = asyncio.Semaphore(max_concurrent)
        tasks = [
            throttled_check(pool.get_device(name), semaphore)
            for name in device_names
        ]
    else:
        tasks = [
            mock_health_check(pool.get_device(name))
            for name in device_names
        ]

    results = await asyncio.gather(*tasks, return_exceptions=True)
    elapsed = time.perf_counter() - start

    # Tally results
    healthy = degraded = critical = errors = 0
    latencies = []

    for result in results:
        if isinstance(result, Exception):
            errors += 1
            critical += 1
        elif result.status == "healthy":
            healthy += 1
            latencies.append(result.latency_ms)
        elif result.status == "degraded":
            degraded += 1
            latencies.append(result.latency_ms)
        else:
            critical += 1

    return {
        "total_devices": len(device_names),
        "elapsed_seconds": round(elapsed, 3),
        "devices_per_second": round(len(device_names) / elapsed, 1),
        "max_concurrent": max_concurrent if use_throttling else "unlimited",
        "summary": {
            "healthy": healthy,
            "degraded": degraded,
            "critical": critical,
            "errors": errors
        },
        "latency_stats": {
            "avg_ms": round(mean(latencies), 1) if latencies else 0,
            "min_ms": round(min(latencies), 1) if latencies else 0,
            "max_ms": round(max(latencies), 1) if latencies else 0,
        }
    }


def format_result(result: dict, label: str = "") -> str:
    """Pretty print test results"""
    lines = []
    if label:
        lines.append(f"\n{'='*60}")
        lines.append(f"  {label}")
        lines.append(f"{'='*60}")

    lines.append(f"  Devices:        {result['total_devices']}")
    lines.append(f"  Concurrency:    {result['max_concurrent']}")
    lines.append(f"  Total Time:     {result['elapsed_seconds']:.2f}s")
    lines.append(f"  Throughput:     {result['devices_per_second']:.0f} devices/sec")
    lines.append(f"  Healthy:        {result['summary']['healthy']}")
    lines.append(f"  Degraded:       {result['summary']['degraded']}")
    lines.append(f"  Critical:       {result['summary']['critical']}")
    if result['summary']['errors']:
        lines.append(f"  Errors:         {result['summary']['errors']}")
    lines.append(f"  Avg Latency:    {result['latency_stats']['avg_ms']:.0f}ms")

    return "\n".join(lines)


async def test_scaling(device_counts: list[int], concurrency: int = 20):
    """Test scaling across different device counts"""
    print("\n" + "="*60)
    print("  SCALE TEST: Health Checks at Different Device Counts")
    print("="*60)
    print(f"  Concurrency limit: {concurrency}")
    print(f"  Simulated latency: 50-200ms per device")

    results = []
    for count in device_counts:
        pool = MockDevicePool(count, fail_rate=0.02)  # 2% failure rate

        # Track memory
        tracemalloc.start()
        result = await run_health_check_all(pool, max_concurrent=concurrency)
        current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        result['memory_mb'] = round(peak / 1024 / 1024, 1)
        results.append(result)

        print(f"\n  {count:,} devices: {result['elapsed_seconds']:.1f}s "
              f"({result['devices_per_second']:.0f}/sec, "
              f"{result['memory_mb']}MB peak)")

    return results


async def test_concurrency_limits(device_count: int = 500):
    """Find optimal concurrency limit"""
    print("\n" + "="*60)
    print("  CONCURRENCY OPTIMIZATION TEST")
    print("="*60)
    print(f"  Testing with {device_count} devices")
    print(f"  Finding optimal semaphore limit...")

    limits = [5, 10, 20, 50, 100, 200, 500]
    results = []

    for limit in limits:
        pool = MockDevicePool(device_count, latency_range=(100, 150))
        result = await run_health_check_all(pool, max_concurrent=limit)
        results.append((limit, result['elapsed_seconds'], result['devices_per_second']))
        print(f"    Limit {limit:3d}: {result['elapsed_seconds']:.2f}s ({result['devices_per_second']:.0f}/sec)")

    # Find optimal
    best = max(results, key=lambda x: x[2])
    print(f"\n  Optimal concurrency: {best[0]} ({best[2]:.0f} devices/sec)")

    return results


async def test_failure_scenarios(device_count: int = 200):
    """Test behavior under different failure rates"""
    print("\n" + "="*60)
    print("  FAILURE INJECTION TEST")
    print("="*60)
    print(f"  Testing {device_count} devices with varying failure rates")

    fail_rates = [0.0, 0.05, 0.10, 0.25, 0.50]

    for rate in fail_rates:
        pool = MockDevicePool(device_count, fail_rate=rate)
        result = await run_health_check_all(pool, max_concurrent=50)

        pct_healthy = result['summary']['healthy'] / device_count * 100
        print(f"    {rate*100:5.1f}% fail rate: {pct_healthy:.1f}% healthy, "
              f"{result['elapsed_seconds']:.2f}s")


async def test_memory_stress(max_devices: int = 5000):
    """Test memory usage at extreme scale"""
    print("\n" + "="*60)
    print("  MEMORY STRESS TEST")
    print("="*60)

    tracemalloc.start()
    pool = MockDevicePool(max_devices, latency_range=(10, 20))  # Fast to focus on memory

    snapshot_before = tracemalloc.take_snapshot()
    result = await run_health_check_all(pool, max_concurrent=100)
    snapshot_after = tracemalloc.take_snapshot()

    current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    print(f"  Devices:      {max_devices:,}")
    print(f"  Time:         {result['elapsed_seconds']:.2f}s")
    print(f"  Throughput:   {result['devices_per_second']:.0f} devices/sec")
    print(f"  Peak Memory:  {peak / 1024 / 1024:.1f} MB")
    print(f"  Per Device:   {peak / max_devices:.0f} bytes")

    # Top memory consumers
    top_stats = snapshot_after.compare_to(snapshot_before, 'lineno')
    print(f"\n  Top memory allocations:")
    for stat in top_stats[:5]:
        print(f"    {stat}")


async def compare_throttled_vs_unlimited(device_count: int = 100):
    """Compare throttled vs unlimited concurrency"""
    print("\n" + "="*60)
    print("  THROTTLED vs UNLIMITED COMPARISON")
    print("="*60)

    pool = MockDevicePool(device_count)

    # Unlimited
    result_unlimited = await run_health_check_all(pool, use_throttling=False)
    print(f"\n  Unlimited:     {result_unlimited['elapsed_seconds']:.2f}s "
          f"({result_unlimited['devices_per_second']:.0f}/sec)")

    # Throttled (default 20)
    result_throttled = await run_health_check_all(pool, max_concurrent=20)
    print(f"  Throttled(20): {result_throttled['elapsed_seconds']:.2f}s "
          f"({result_throttled['devices_per_second']:.0f}/sec)")

    # Throttled (aggressive)
    result_throttled_50 = await run_health_check_all(pool, max_concurrent=50)
    print(f"  Throttled(50): {result_throttled_50['elapsed_seconds']:.2f}s "
          f"({result_throttled_50['devices_per_second']:.0f}/sec)")


async def run_full_suite():
    """Run all tests"""
    print("\n" + "#"*60)
    print("#" + " "*20 + "SCALE TEST SUITE" + " "*22 + "#")
    print("#"*60)

    # 1. Scale test
    await test_scaling([50, 100, 250, 500, 1000])

    # 2. Concurrency optimization
    await test_concurrency_limits(500)

    # 3. Throttled vs unlimited
    await compare_throttled_vs_unlimited(200)

    # 4. Failure scenarios
    await test_failure_scenarios(200)

    # 5. Memory stress
    await test_memory_stress(2000)

    print("\n" + "="*60)
    print("  SUMMARY")
    print("="*60)
    print("""
  Key findings will vary by system, but typical results:

  - 100 devices @ 50 concurrent: ~0.3s (300+ devices/sec)
  - 500 devices @ 50 concurrent: ~1.3s (380+ devices/sec)
  - 1000 devices @ 50 concurrent: ~2.5s (400+ devices/sec)

  Bottlenecks:
  - Semaphore limit directly affects throughput
  - Memory scales linearly (~1KB per device)
  - Real SSH latency (100-300ms) is the actual limit

  For real devices with 150ms avg latency:
  - 50 concurrent = ~330 devices/sec theoretical max
  - 100 concurrent = ~660 devices/sec theoretical max
  - VTY line limits (5-16) reduce this significantly
    """)


def main():
    parser = argparse.ArgumentParser(description="Scale test for health checks")
    parser.add_argument("--devices", type=int, default=500, help="Number of mock devices")
    parser.add_argument("--concurrency", type=int, default=20, help="Max concurrent connections")
    parser.add_argument("--fail-rate", type=float, default=0.02, help="Device failure rate (0.0-1.0)")
    parser.add_argument("--find-optimal", action="store_true", help="Run concurrency optimization test")
    parser.add_argument("--full-suite", action="store_true", help="Run full test suite")
    parser.add_argument("--memory-test", action="store_true", help="Run memory stress test")

    args = parser.parse_args()

    if args.full_suite:
        asyncio.run(run_full_suite())
    elif args.find_optimal:
        asyncio.run(test_concurrency_limits(args.devices))
    elif args.memory_test:
        asyncio.run(test_memory_stress(args.devices))
    else:
        # Single run
        async def single_test():
            pool = MockDevicePool(args.devices, fail_rate=args.fail_rate)
            result = await run_health_check_all(pool, max_concurrent=args.concurrency)
            print(format_result(result, f"Health Check: {args.devices} Devices"))

        asyncio.run(single_test())


if __name__ == "__main__":
    main()
