#!/usr/bin/env python3
"""
Cached-Only Load Test - Tests pure API capacity without device SSH.
"""

import time
import asyncio
import aiohttp
from datetime import datetime
from statistics import mean

API_BASE = "http://localhost:5001"
TOTAL_REQUESTS = 5000
CONCURRENT = 500

# Only cached/fast endpoints
ENDPOINTS = ["/healthz", "/api/devices", "/readyz"]


async def make_request(session, endpoint, semaphore):
    async with semaphore:
        start = time.perf_counter()
        try:
            async with session.get(f"{API_BASE}{endpoint}", timeout=aiohttp.ClientTimeout(total=10)) as resp:
                await resp.read()
                return (time.perf_counter() - start) * 1000, resp.status == 200
        except Exception:
            return (time.perf_counter() - start) * 1000, False


async def main():
    print("=" * 60)
    print("  CACHED-ONLY 5000 CONNECTION TEST")
    print("=" * 60)

    connector = aiohttp.TCPConnector(limit=CONCURRENT)
    async with aiohttp.ClientSession(connector=connector) as session:
        # Warm cache
        for ep in ENDPOINTS:
            await make_request(session, ep, asyncio.Semaphore(1))

        print(f"\n  Sending {TOTAL_REQUESTS} requests ({CONCURRENT} concurrent)...\n")

        semaphore = asyncio.Semaphore(CONCURRENT)
        endpoints = [ENDPOINTS[i % len(ENDPOINTS)] for i in range(TOTAL_REQUESTS)]

        start = time.perf_counter()
        tasks = [make_request(session, ep, semaphore) for ep in endpoints]
        results = await asyncio.gather(*tasks)
        total_time = time.perf_counter() - start

        times = [r[0] for r in results if r[1]]
        success = sum(1 for r in results if r[1])

        print(f"  Results:")
        print(f"    Total Time:   {total_time:.2f}s")
        print(f"    Throughput:   {TOTAL_REQUESTS/total_time:.0f} req/sec")
        print(f"    Success Rate: {success/TOTAL_REQUESTS*100:.1f}%")
        print(f"    Avg Latency:  {mean(times):.1f}ms" if times else "")
        print(f"    P50 Latency:  {sorted(times)[len(times)//2]:.1f}ms" if times else "")
        print(f"    P95 Latency:  {sorted(times)[int(len(times)*0.95)]:.1f}ms" if times else "")

        if success/TOTAL_REQUESTS >= 0.95:
            print(f"\n  ✅ API can handle {TOTAL_REQUESTS/total_time:.0f} req/sec (cached)")


if __name__ == "__main__":
    asyncio.run(main())
