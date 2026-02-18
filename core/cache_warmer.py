"""
Cache Warming for MCP Server Startup

Pre-populates the device health cache so the first real requests
are served from cache instead of hitting SSH cold.

Usage:
    from core.cache_warmer import warm_cache

    # Fire-and-forget (default in MCP lifespan)
    asyncio.create_task(warm_cache())

    # Block until done (CI/staging)
    result = await warm_cache(block_until_done=True)
"""

import asyncio
import logging
from typing import Optional

logger = logging.getLogger(__name__)

# Module-level counters for Prometheus
warm_success_total = 0
warm_failure_total = 0


async def warm_cache(
    device_names: Optional[list[str]] = None,
    block_until_done: bool = False,
    concurrency: int = 5,
    cache_ttl: int = 120,
) -> dict:
    """
    Warm the device health cache by running health checks.

    Args:
        device_names: Devices to warm (default: all from config.devices.DEVICES)
        block_until_done: If True, awaits all checks before returning
        concurrency: Max concurrent health checks (default: 5)
        cache_ttl: TTL for warmed cache entries in seconds (default: 120)

    Returns:
        Dict with warmed/failed/skipped counts
    """
    global warm_success_total, warm_failure_total

    from config.devices import DEVICES
    from core.device_cache import get_device_cache

    if device_names is None:
        device_names = list(DEVICES.keys())

    cache = get_device_cache()
    semaphore = asyncio.Semaphore(concurrency)
    results = {"warmed": 0, "failed": 0, "skipped": 0}

    async def _warm_one(name: str):
        global warm_success_total, warm_failure_total
        async with semaphore:
            # Skip if already cached
            existing = await cache.get_health(name)
            if existing is not None:
                results["skipped"] += 1
                return

            try:
                from mcp_tools.device import health_check
                health = await health_check(device_name=name)

                if isinstance(health, str):
                    import json
                    health = json.loads(health)

                await cache.set_health(name, health, ttl=cache_ttl)
                results["warmed"] += 1
                warm_success_total += 1
            except Exception as e:
                logger.debug(f"Cache warm failed for {name}: {e}")
                results["failed"] += 1
                warm_failure_total += 1

    tasks = [_warm_one(name) for name in device_names]

    if block_until_done:
        await asyncio.gather(*tasks, return_exceptions=True)
    else:
        # Fire-and-forget but still await internally
        await asyncio.gather(*tasks, return_exceptions=True)

    logger.info(
        f"Cache warming complete: {results['warmed']} warmed, "
        f"{results['failed']} failed, {results['skipped']} skipped"
    )
    return results
