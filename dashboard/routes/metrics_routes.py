"""
Prometheus Metrics API Routes.

Extracted from api_server.py lines 1404-1693.
Provides /metrics and /metrics/devices endpoints for Prometheus scraping.
"""

import logging
import time
import asyncio
from datetime import datetime, timezone
from threading import Thread

from flask import Blueprint, request, g

logger = logging.getLogger(__name__)

metrics_bp = Blueprint('metrics', __name__)

# Simple metrics storage
_metrics = {
    'requests_total': 0,
    'requests_by_endpoint': {},
    'requests_by_status': {},
    'response_time_sum': 0,
    'response_time_count': 0,
    'cache_hits': 0,
    'cache_misses': 0,
    'errors_total': 0,
    'start_time': datetime.now(timezone.utc).isoformat(),
}

# Device metrics cache (updated by background collector every 30 seconds)
_device_metrics_cache = {
    'switches': {},
    'linux': {},
    'containerlab': {},
    'last_update': None,
    'collector_running': False,
}


@metrics_bp.before_app_request
def before_request_metrics():
    """Track request start time for latency calculation."""
    g.metrics_start_time = time.time()


@metrics_bp.after_app_request
def after_request_metrics(response):
    """Record request metrics after each request."""
    if request.path == '/metrics':
        return response

    _metrics['requests_total'] += 1

    endpoint = request.endpoint or 'unknown'
    _metrics['requests_by_endpoint'][endpoint] = _metrics['requests_by_endpoint'].get(endpoint, 0) + 1

    status = str(response.status_code)
    _metrics['requests_by_status'][status] = _metrics['requests_by_status'].get(status, 0) + 1

    if hasattr(g, 'metrics_start_time'):
        elapsed = time.time() - g.metrics_start_time
        _metrics['response_time_sum'] += elapsed
        _metrics['response_time_count'] += 1

    if response.status_code >= 400:
        _metrics['errors_total'] += 1

    return response


@metrics_bp.route('/metrics')
def prometheus_metrics():
    """Prometheus-compatible metrics endpoint."""
    lines = []

    lines.append('# HELP networkops_requests_total Total number of HTTP requests')
    lines.append('# TYPE networkops_requests_total counter')
    lines.append(f'networkops_requests_total {_metrics["requests_total"]}')

    lines.append('# HELP networkops_requests_by_status HTTP requests by status code')
    lines.append('# TYPE networkops_requests_by_status counter')
    for status, count in _metrics['requests_by_status'].items():
        lines.append(f'networkops_requests_by_status{{status="{status}"}} {count}')

    lines.append('# HELP networkops_response_time_seconds_sum Sum of response times')
    lines.append('# TYPE networkops_response_time_seconds_sum counter')
    lines.append(f'networkops_response_time_seconds_sum {_metrics["response_time_sum"]:.6f}')

    lines.append('# HELP networkops_response_time_seconds_count Number of requests for avg calculation')
    lines.append('# TYPE networkops_response_time_seconds_count counter')
    lines.append(f'networkops_response_time_seconds_count {_metrics["response_time_count"]}')

    if _metrics['response_time_count'] > 0:
        avg_time = _metrics['response_time_sum'] / _metrics['response_time_count']
        lines.append('# HELP networkops_response_time_avg_seconds Average response time')
        lines.append('# TYPE networkops_response_time_avg_seconds gauge')
        lines.append(f'networkops_response_time_avg_seconds {avg_time:.6f}')

    lines.append('# HELP networkops_errors_total Total number of error responses (4xx, 5xx)')
    lines.append('# TYPE networkops_errors_total counter')
    lines.append(f'networkops_errors_total {_metrics["errors_total"]}')

    # Cache stats
    try:
        from dashboard.extensions import cache
        cache_type = cache.config.get('CACHE_TYPE', 'simple')
        if cache_type == 'redis':
            import redis
            from config.settings import get_settings
            settings = get_settings()
            redis_client = redis.from_url(settings.redis.redis_url)
            info = redis_client.info()
            lines.append('# HELP networkops_redis_connected Redis connection status')
            lines.append('# TYPE networkops_redis_connected gauge')
            lines.append('networkops_redis_connected 1')
            lines.append('# HELP networkops_redis_used_memory_bytes Redis memory usage')
            lines.append('# TYPE networkops_redis_used_memory_bytes gauge')
            lines.append(f'networkops_redis_used_memory_bytes {info.get("used_memory", 0)}')
            lines.append('# HELP networkops_redis_connected_clients Number of Redis clients')
            lines.append('# TYPE networkops_redis_connected_clients gauge')
            lines.append(f'networkops_redis_connected_clients {info.get("connected_clients", 0)}')
            api_keys = list(redis_client.scan_iter(match='flask_cache_*'))
            lines.append('# HELP networkops_cache_keys Number of cached API responses')
            lines.append('# TYPE networkops_cache_keys gauge')
            lines.append(f'networkops_cache_keys {len(api_keys)}')
    except Exception:
        lines.append('# HELP networkops_redis_connected Redis connection status')
        lines.append('# TYPE networkops_redis_connected gauge')
        lines.append('networkops_redis_connected 0')

    # Health checks
    try:
        from dashboard.routes.health import check_redis_health, check_postgres_health, check_celery_health
        redis_ok, _ = check_redis_health()
        postgres_ok, _ = check_postgres_health()
        celery_ok, _ = check_celery_health()
        lines.append('# HELP networkops_health_redis Redis health status')
        lines.append('# TYPE networkops_health_redis gauge')
        lines.append(f'networkops_health_redis {1 if redis_ok else 0}')
        lines.append('# HELP networkops_health_postgres PostgreSQL health status')
        lines.append('# TYPE networkops_health_postgres gauge')
        lines.append(f'networkops_health_postgres {1 if postgres_ok else 0}')
        lines.append('# HELP networkops_health_celery Celery worker health status')
        lines.append('# TYPE networkops_health_celery gauge')
        lines.append(f'networkops_health_celery {1 if celery_ok else 0}')
    except Exception:
        pass

    # Uptime
    lines.append('# HELP networkops_start_time_seconds Server start time as Unix timestamp')
    lines.append('# TYPE networkops_start_time_seconds gauge')
    lines.append(f'networkops_start_time_seconds {datetime.fromisoformat(_metrics["start_time"]).timestamp():.0f}')

    # Top endpoints
    lines.append('# HELP networkops_endpoint_requests Requests per endpoint')
    lines.append('# TYPE networkops_endpoint_requests counter')
    for endpoint, count in sorted(_metrics['requests_by_endpoint'].items(), key=lambda x: -x[1])[:20]:
        lines.append(f'networkops_endpoint_requests{{endpoint="{endpoint}"}} {count}')

    # ---- MCP Tool Metrics ----
    try:
        from core.tool_metrics import tool_metrics
        prom = tool_metrics.to_prometheus_format()
        if prom:
            lines.append('')
            lines.append(prom)
    except Exception:
        pass

    # ---- Connection Pool Stats ----
    try:
        from core.connection_pool import get_connection_pool
        pool_stats = get_connection_pool().get_stats()
        lines.append('')
        lines.append('# HELP mcp_pool_connections_created Total SSH connections created')
        lines.append('# TYPE mcp_pool_connections_created counter')
        lines.append(f'mcp_pool_connections_created {pool_stats.get("connections_created", 0)}')
        lines.append('# HELP mcp_pool_connections_reused Total SSH connections reused from pool')
        lines.append('# TYPE mcp_pool_connections_reused counter')
        lines.append(f'mcp_pool_connections_reused {pool_stats.get("connections_reused", 0)}')
        lines.append('# HELP mcp_pool_connections_failed Total SSH connection failures')
        lines.append('# TYPE mcp_pool_connections_failed counter')
        lines.append(f'mcp_pool_connections_failed {pool_stats.get("connections_failed", 0)}')
        lines.append('# HELP mcp_pool_hit_rate Connection pool hit rate percentage')
        lines.append('# TYPE mcp_pool_hit_rate gauge')
        lines.append(f'mcp_pool_hit_rate {pool_stats.get("hit_rate", 0):.2f}')
    except Exception:
        pass

    # ---- Circuit Breaker Status ----
    try:
        from core.circuit_breaker import get_all_circuit_status
        for service, status in get_all_circuit_status().items():
            closed = 1 if status.state.value == "closed" else 0
            lines.append(f'mcp_circuit_breaker_closed{{service="{service}"}} {closed}')
    except Exception:
        pass

    # ---- Cache Warmer Counters ----
    try:
        from core.cache_warmer import warm_success_total, warm_failure_total
        lines.append('')
        lines.append('# HELP mcp_cache_warm_success_total Devices successfully cache-warmed')
        lines.append('# TYPE mcp_cache_warm_success_total counter')
        lines.append(f'mcp_cache_warm_success_total {warm_success_total}')
        lines.append('# HELP mcp_cache_warm_failure_total Devices that failed cache warming')
        lines.append('# TYPE mcp_cache_warm_failure_total counter')
        lines.append(f'mcp_cache_warm_failure_total {warm_failure_total}')
    except Exception:
        pass

    response_text = '\n'.join(lines) + '\n'
    return response_text, 200, {'Content-Type': 'text/plain; charset=utf-8'}


@metrics_bp.route('/metrics/devices')
def device_metrics():
    """Prometheus-compatible metrics for all network devices."""
    from dashboard.telemetry_store import get_telemetry_store

    telemetry_data = get_telemetry_store()
    lines = []

    # Metric definitions
    lines.append('# HELP network_device_up Device availability (1=up, 0=down)')
    lines.append('# TYPE network_device_up gauge')
    lines.append('# HELP network_device_cpu_percent CPU utilization percentage')
    lines.append('# TYPE network_device_cpu_percent gauge')
    lines.append('# HELP network_device_memory_percent Memory utilization percentage')
    lines.append('# TYPE network_device_memory_percent gauge')
    lines.append('# HELP network_device_memory_used_bytes Memory used in bytes')
    lines.append('# TYPE network_device_memory_used_bytes gauge')
    lines.append('# HELP network_device_disk_percent Disk utilization percentage (Linux only)')
    lines.append('# TYPE network_device_disk_percent gauge')
    lines.append('# HELP network_interface_in_octets Interface input bytes')
    lines.append('# TYPE network_interface_in_octets counter')
    lines.append('# HELP network_interface_out_octets Interface output bytes')
    lines.append('# TYPE network_interface_out_octets counter')
    lines.append('# HELP network_bgp_peers_established Number of established BGP peers')
    lines.append('# TYPE network_bgp_peers_established gauge')

    # Cisco Routers (from MDT telemetry)
    try:
        interface_stats = telemetry_data.get_interface_stats()
        cpu_stats = telemetry_data.get_cpu_stats()
        memory_stats = telemetry_data.get_memory_stats()

        for device, interfaces in interface_stats.items():
            if device.startswith('Switch-'):
                continue
            lines.append(f'network_device_up{{device="{device}",type="router"}} 1')
            for intf, stats in interfaces.items():
                intf_label = intf.replace('/', '_').replace('.', '_')
                in_octets = stats.get('in_octets', 0)
                out_octets = stats.get('out_octets', 0)
                lines.append(f'network_interface_in_octets{{device="{device}",interface="{intf_label}",type="router"}} {in_octets}')
                lines.append(f'network_interface_out_octets{{device="{device}",interface="{intf_label}",type="router"}} {out_octets}')

        for device, cpu in cpu_stats.items():
            if device.startswith('Switch-'):
                continue
            lines.append(f'network_device_cpu_percent{{device="{device}",type="router"}} {cpu.get("five_seconds", 0)}')

        for device, mem in memory_stats.items():
            if device.startswith('Switch-'):
                continue
            lines.append(f'network_device_memory_used_bytes{{device="{device}",type="router"}} {mem.get("used", 0)}')
            lines.append(f'network_device_memory_percent{{device="{device}",type="router"}} {mem.get("percent_used", 0)}')

    except Exception as e:
        logger.warning(f"Failed to get MDT telemetry metrics: {e}")

    # Router BGP
    for device, data in _device_metrics_cache.get('router_bgp', {}).items():
        lines.append(f'network_bgp_peers_established{{device="{device}",type="router"}} {data.get("bgp_peers", 0)}')

    # Switches
    for device, data in _device_metrics_cache.get('switches', {}).items():
        up = 1 if data.get('up', False) else 0
        lines.append(f'network_device_up{{device="{device}",type="switch"}} {up}')
        if up:
            lines.append(f'network_device_cpu_percent{{device="{device}",type="switch"}} {data.get("cpu", 0)}')
            lines.append(f'network_device_memory_percent{{device="{device}",type="switch"}} {data.get("memory", 0)}')

    # Linux Hosts
    for device, data in _device_metrics_cache.get('linux', {}).items():
        up = 1 if data.get('up', False) else 0
        lines.append(f'network_device_up{{device="{device}",type="linux"}} {up}')
        if up:
            lines.append(f'network_device_cpu_percent{{device="{device}",type="linux"}} {data.get("cpu", 0)}')
            lines.append(f'network_device_memory_percent{{device="{device}",type="linux"}} {data.get("memory", 0)}')
            lines.append(f'network_device_disk_percent{{device="{device}",type="linux"}} {data.get("disk", 0)}')

    # Containerlab
    for device, data in _device_metrics_cache.get('containerlab', {}).items():
        up = 1 if data.get('up', False) else 0
        lines.append(f'network_device_up{{device="{device}",type="containerlab"}} {up}')
        if up:
            lines.append(f'network_device_cpu_percent{{device="{device}",type="containerlab"}} {data.get("cpu", 0)}')
            lines.append(f'network_device_memory_percent{{device="{device}",type="containerlab"}} {data.get("memory", 0)}')
            if 'bgp_peers' in data:
                lines.append(f'network_bgp_peers_established{{device="{device}"}} {data.get("bgp_peers", 0)}')

    last_update = _device_metrics_cache.get('last_update')
    if last_update:
        lines.append(f'# Cache last updated: {last_update.isoformat()}')

    response_text = '\n'.join(lines) + '\n'
    return response_text, 200, {'Content-Type': 'text/plain; charset=utf-8'}


def start_device_metrics_collector():
    """Start background thread that collects metrics from switches, Linux, containerlab."""
    def collector_loop():
        logger.info("Device metrics collector started (30-second interval)")
        _device_metrics_cache['collector_running'] = True

        while True:
            try:
                from collectors import (
                    collect_switch_metrics,
                    collect_linux_metrics,
                    collect_containerlab_metrics,
                    collect_router_bgp_metrics,
                )

                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)

                try:
                    results = loop.run_until_complete(asyncio.gather(
                        collect_switch_metrics(),
                        collect_linux_metrics(),
                        collect_containerlab_metrics(),
                        collect_router_bgp_metrics(),
                        return_exceptions=True
                    ))

                    for idx, key in enumerate(['switches', 'linux', 'containerlab', 'router_bgp']):
                        if not isinstance(results[idx], Exception):
                            _device_metrics_cache[key] = results[idx]
                        else:
                            logger.warning(f"{key} collection failed: {results[idx]}")

                    _device_metrics_cache['last_update'] = datetime.now(timezone.utc)

                finally:
                    loop.close()

            except ImportError as e:
                logger.warning(f"Collectors not available: {e}")
            except Exception as e:
                logger.error(f"Device metrics collection failed: {e}")

            time.sleep(30)

    thread = Thread(target=collector_loop, daemon=True, name="DeviceMetricsCollector")
    thread.start()
    return thread
