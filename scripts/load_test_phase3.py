#!/usr/bin/env python3
"""
Phase 3 Enterprise Scale Test - 500+ Simulated Devices

Tests the full production stack:
- Sync API with Redis caching
- Async job processing with Celery
- Health endpoint performance
- Burst traffic handling

Run with: python scripts/load_test_phase3.py
"""

import time
import asyncio
import aiohttp
import json
from statistics import mean, stdev, median
from dataclasses import dataclass, asdict
from typing import Optional
from datetime import datetime

# Configuration
API_BASE = "http://localhost:5001"

# Scale settings - increase these to stress test
SIMULATED_DEVICES = 1000     # Total simulated devices
CONCURRENT_REQUESTS = 100    # Parallel requests at once
BURST_SIZE = 500             # Burst traffic test size

# Real device rotation (we spread simulated load across real devices)
IOS_XE_DEVICES = ["R1", "R2", "R3", "R4", "Switch-R1", "Switch-R2", "Switch-R4"]


@dataclass
class RequestResult:
    endpoint: str
    device: str
    response_time_ms: float
    success: bool
    status_code: int
    cached: bool  # <50ms considered cached


@dataclass
class TestResult:
    test_name: str
    total_requests: int
    successful: int
    failed: int
    total_time_ms: float
    throughput_rps: float
    avg_response_ms: float
    p50_response_ms: float
    p95_response_ms: float
    p99_response_ms: float
    cache_hit_rate: float
    error_rate: float


async def make_request(
    session: aiohttp.ClientSession,
    endpoint: str,
    device: Optional[str] = None,
    method: str = "GET",
    json_data: dict = None
) -> RequestResult:
    """Make a single API request and measure response time."""
    if device and "?" in endpoint:
        url = f"{API_BASE}{endpoint}&device={device}"
    elif device:
        url = f"{API_BASE}{endpoint}?device={device}"
    else:
        url = f"{API_BASE}{endpoint}"

    start = time.perf_counter()
    try:
        if method == "POST":
            async with session.post(url, json=json_data, timeout=aiohttp.ClientTimeout(total=60)) as resp:
                await resp.read()
                elapsed_ms = (time.perf_counter() - start) * 1000
                return RequestResult(
                    endpoint=endpoint,
                    device=device or "N/A",
                    response_time_ms=elapsed_ms,
                    success=resp.status in (200, 201, 202),
                    status_code=resp.status,
                    cached=elapsed_ms < 50
                )
        else:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=60)) as resp:
                await resp.read()
                elapsed_ms = (time.perf_counter() - start) * 1000
                return RequestResult(
                    endpoint=endpoint,
                    device=device or "N/A",
                    response_time_ms=elapsed_ms,
                    success=resp.status == 200,
                    status_code=resp.status,
                    cached=elapsed_ms < 50
                )
    except Exception as e:
        elapsed_ms = (time.perf_counter() - start) * 1000
        return RequestResult(
            endpoint=endpoint,
            device=device or "N/A",
            response_time_ms=elapsed_ms,
            success=False,
            status_code=0,
            cached=False
        )


def analyze_results(results: list[RequestResult], test_name: str, total_time_ms: float) -> TestResult:
    """Analyze test results and compute statistics."""
    successful = [r for r in results if r.success]
    times = [r.response_time_ms for r in successful]
    cached = [r for r in successful if r.cached]

    if not times:
        times = [0]

    sorted_times = sorted(times)

    return TestResult(
        test_name=test_name,
        total_requests=len(results),
        successful=len(successful),
        failed=len(results) - len(successful),
        total_time_ms=total_time_ms,
        throughput_rps=len(results) / (total_time_ms / 1000) if total_time_ms > 0 else 0,
        avg_response_ms=mean(times),
        p50_response_ms=sorted_times[len(sorted_times) // 2],
        p95_response_ms=sorted_times[int(len(sorted_times) * 0.95)] if len(sorted_times) > 1 else sorted_times[0],
        p99_response_ms=sorted_times[int(len(sorted_times) * 0.99)] if len(sorted_times) > 1 else sorted_times[0],
        cache_hit_rate=len(cached) / len(successful) * 100 if successful else 0,
        error_rate=(len(results) - len(successful)) / len(results) * 100 if results else 0
    )


def print_result(result: TestResult):
    """Print test result in a nice format."""
    print(f"\n  Results:")
    print(f"    Requests: {result.successful}/{result.total_requests} successful ({result.error_rate:.1f}% errors)")
    print(f"    Total time: {result.total_time_ms:.0f}ms")
    print(f"    Throughput: {result.throughput_rps:.1f} req/sec")
    print(f"    Response times:")
    print(f"      Average: {result.avg_response_ms:.1f}ms")
    print(f"      P50: {result.p50_response_ms:.1f}ms")
    print(f"      P95: {result.p95_response_ms:.1f}ms")
    print(f"      P99: {result.p99_response_ms:.1f}ms")
    print(f"    Cache hit rate: {result.cache_hit_rate:.1f}%")


async def test_health_endpoints(session: aiohttp.ClientSession) -> TestResult:
    """Test health endpoint performance (critical for load balancers)."""
    print("\n" + "=" * 70)
    print("TEST 1: Health Endpoints (Kubernetes/LB readiness)")
    print("=" * 70)

    endpoints = ["/healthz", "/readyz", "/health/detailed"]

    # 100 rapid health checks (simulating aggressive LB probing)
    tasks = []
    for i in range(100):
        endpoint = endpoints[i % len(endpoints)]
        tasks.append(make_request(session, endpoint))

    print(f"\n  Firing 100 health checks across 3 endpoints...")

    start = time.perf_counter()
    results = await asyncio.gather(*tasks)
    total_time = (time.perf_counter() - start) * 1000

    test_result = analyze_results(results, "Health Endpoints", total_time)
    print_result(test_result)

    return test_result


async def test_device_monitoring_scale(session: aiohttp.ClientSession) -> TestResult:
    """Test monitoring at enterprise scale - 500 simulated devices."""
    print("\n" + "=" * 70)
    print(f"TEST 2: Device Monitoring ({SIMULATED_DEVICES} simulated devices)")
    print("=" * 70)

    all_results = []
    batch_size = CONCURRENT_REQUESTS
    total_batches = SIMULATED_DEVICES // batch_size

    print(f"\n  Processing {SIMULATED_DEVICES} devices in {total_batches} batches of {batch_size}...")
    print(f"  API calls per device: 2 (interface-stats + health)")
    print(f"  Total API calls: {SIMULATED_DEVICES * 2}")

    start = time.perf_counter()

    for batch_num in range(total_batches):
        tasks = []
        for i in range(batch_size):
            device_id = batch_num * batch_size + i
            device_name = IOS_XE_DEVICES[device_id % len(IOS_XE_DEVICES)]

            # Two calls per device - use actual endpoints
            tasks.append(make_request(session, "/api/interface-stats", device_name))
            tasks.append(make_request(session, "/api/bgp-summary", device_name))

        batch_results = await asyncio.gather(*tasks)
        all_results.extend(batch_results)

        if (batch_num + 1) % 5 == 0:
            elapsed = (time.perf_counter() - start) * 1000
            print(f"    Processed {(batch_num + 1) * batch_size} devices... ({elapsed:.0f}ms)")

    total_time = (time.perf_counter() - start) * 1000

    test_result = analyze_results(all_results, f"{SIMULATED_DEVICES}-Device Monitoring", total_time)
    print_result(test_result)

    # Per-endpoint breakdown
    print(f"\n  By Endpoint:")
    for endpoint in ["/api/interface-stats", "/api/bgp-summary"]:
        ep_results = [r for r in all_results if r.success and endpoint in r.endpoint]
        if ep_results:
            times = [r.response_time_ms for r in ep_results]
            cached = sum(1 for r in ep_results if r.cached)
            print(f"    {endpoint}: avg {mean(times):.1f}ms, cache {cached}/{len(ep_results)} ({cached/len(ep_results)*100:.0f}%)")

    return test_result


async def test_burst_traffic(session: aiohttp.ClientSession) -> TestResult:
    """Test handling of burst traffic."""
    print("\n" + "=" * 70)
    print(f"TEST 3: Burst Traffic ({BURST_SIZE} simultaneous requests)")
    print("=" * 70)

    endpoints = [
        "/api/topology",
        "/api/switch-status",
        "/api/dmvpn-status",
        "/api/devices",
        "/healthz",
    ]

    tasks = []
    for i in range(BURST_SIZE):
        endpoint = endpoints[i % len(endpoints)]
        tasks.append(make_request(session, endpoint))

    print(f"\n  Firing {BURST_SIZE} concurrent requests across {len(endpoints)} endpoints...")

    start = time.perf_counter()
    results = await asyncio.gather(*tasks)
    total_time = (time.perf_counter() - start) * 1000

    test_result = analyze_results(results, f"{BURST_SIZE}-Request Burst", total_time)
    print_result(test_result)

    # Check for rate limiting
    rate_limited = [r for r in results if r.status_code == 429]
    if rate_limited:
        print(f"\n  Rate limited: {len(rate_limited)} requests (429 responses)")

    return test_result


async def test_async_job_submission(session: aiohttp.ClientSession) -> TestResult:
    """Test async job submission performance."""
    print("\n" + "=" * 70)
    print("TEST 4: Async Job Submission (Celery queue)")
    print("=" * 70)

    results = []

    # Submit 50 async jobs
    print(f"\n  Submitting 50 async health check jobs...")

    start = time.perf_counter()

    tasks = []
    for i in range(50):
        device = IOS_XE_DEVICES[i % len(IOS_XE_DEVICES)]
        tasks.append(make_request(
            session,
            "/api/jobs",
            method="POST",
            json_data={"task": "health_check", "device": device}
        ))

    results = await asyncio.gather(*tasks)
    total_time = (time.perf_counter() - start) * 1000

    test_result = analyze_results(results, "Async Job Submission", total_time)
    print_result(test_result)

    # Count successful submissions vs rejections
    submitted = [r for r in results if r.status_code in (200, 201, 202)]
    rejected = [r for r in results if r.status_code == 429]
    errors = [r for r in results if r.status_code not in (200, 201, 202, 429)]

    print(f"\n  Job status:")
    print(f"    Submitted: {len(submitted)}")
    print(f"    Rate limited: {len(rejected)}")
    print(f"    Errors: {len(errors)}")

    return test_result


async def test_sustained_load(session: aiohttp.ClientSession, duration_seconds: int = 10) -> TestResult:
    """Test sustained load over time."""
    print("\n" + "=" * 70)
    print(f"TEST 5: Sustained Load ({duration_seconds}s continuous traffic)")
    print("=" * 70)

    endpoints = ["/api/topology", "/api/devices", "/healthz", "/api/switch-status"]
    all_results = []

    print(f"\n  Running {CONCURRENT_REQUESTS} concurrent requests for {duration_seconds}s...")

    start = time.perf_counter()
    end_time = start + duration_seconds
    batch_count = 0

    while time.perf_counter() < end_time:
        tasks = []
        for i in range(CONCURRENT_REQUESTS):
            endpoint = endpoints[i % len(endpoints)]
            tasks.append(make_request(session, endpoint))

        results = await asyncio.gather(*tasks)
        all_results.extend(results)
        batch_count += 1

        # Brief pause to avoid overwhelming
        await asyncio.sleep(0.1)

    total_time = (time.perf_counter() - start) * 1000

    test_result = analyze_results(all_results, f"{duration_seconds}s Sustained Load", total_time)
    print_result(test_result)
    print(f"\n  Total batches: {batch_count}")
    print(f"  Total requests: {len(all_results)}")

    return test_result


async def main():
    print("=" * 70)
    print("    NETWORKOPS PHASE 3 ENTERPRISE SCALE TEST")
    print("=" * 70)
    print(f"\nTimestamp: {datetime.now().isoformat()}")
    print(f"API Base: {API_BASE}")
    print(f"Configuration:")
    print(f"  Simulated Devices: {SIMULATED_DEVICES}")
    print(f"  Concurrent Requests: {CONCURRENT_REQUESTS}")
    print(f"  Burst Size: {BURST_SIZE}")

    all_test_results = []

    async with aiohttp.ClientSession() as session:
        # Check API health first
        try:
            async with session.get(f"{API_BASE}/healthz", timeout=aiohttp.ClientTimeout(total=5)) as resp:
                if resp.status != 200:
                    print(f"\n[ERROR] API health check failed (status {resp.status})")
                    return
                data = await resp.json()
                print(f"\n[OK] API server is healthy (version: {data.get('version', 'unknown')})")
        except Exception as e:
            print(f"\n[ERROR] Cannot connect to API: {e}")
            return

        # Run all tests
        all_test_results.append(await test_health_endpoints(session))
        all_test_results.append(await test_device_monitoring_scale(session))
        all_test_results.append(await test_burst_traffic(session))
        all_test_results.append(await test_async_job_submission(session))
        all_test_results.append(await test_sustained_load(session, duration_seconds=10))

    # Summary
    print("\n" + "=" * 70)
    print("SCALE TEST SUMMARY")
    print("=" * 70)

    print(f"\n{'Test':<40} {'Req/s':>10} {'Avg ms':>10} {'P95 ms':>10} {'Errors':>10}")
    print("-" * 80)

    for result in all_test_results:
        print(f"{result.test_name:<40} {result.throughput_rps:>10.1f} {result.avg_response_ms:>10.1f} {result.p95_response_ms:>10.1f} {result.error_rate:>9.1f}%")

    # Save results to JSON
    output = {
        "timestamp": datetime.now().isoformat(),
        "configuration": {
            "simulated_devices": SIMULATED_DEVICES,
            "concurrent_requests": CONCURRENT_REQUESTS,
            "burst_size": BURST_SIZE,
        },
        "results": [asdict(r) for r in all_test_results]
    }

    with open("scripts/phase3_load_test_results.json", "w") as f:
        json.dump(output, f, indent=2)

    print(f"\nResults saved to: scripts/phase3_load_test_results.json")

    # Overall assessment
    total_requests = sum(r.total_requests for r in all_test_results)
    avg_throughput = mean(r.throughput_rps for r in all_test_results)
    avg_p95 = mean(r.p95_response_ms for r in all_test_results)

    print(f"\n{'='*70}")
    print("ENTERPRISE READINESS ASSESSMENT")
    print("="*70)
    print(f"\n  Total requests executed: {total_requests}")
    print(f"  Average throughput: {avg_throughput:.1f} req/sec")
    print(f"  Average P95 latency: {avg_p95:.1f}ms")

    if avg_throughput > 500 and avg_p95 < 100:
        print(f"\n  [PASS] System meets enterprise performance targets")
        print(f"         (>500 req/s, <100ms P95)")
    elif avg_throughput > 200 and avg_p95 < 200:
        print(f"\n  [ACCEPTABLE] System meets minimum production requirements")
        print(f"               (>200 req/s, <200ms P95)")
    else:
        print(f"\n  [NEEDS WORK] Performance below production targets")


if __name__ == "__main__":
    asyncio.run(main())
