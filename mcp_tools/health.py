"""
Health checks: Linux hosts, CPU/memory.
"""
import json
import re

from config.devices import DEVICES
from core.scrapli_manager import get_ios_xe_connection, get_linux_connection
from ._ops_helpers import is_cisco_device, is_linux_device


async def linux_health_check(device_name: str) -> str:
    """Run health check on a Linux host - checks uptime, memory, disk, and network"""
    if device_name not in DEVICES:
        return json.dumps({"error": f"Device '{device_name}' not found"})

    if not is_linux_device(device_name):
        return json.dumps({"error": f"Device '{device_name}' is not a Linux host"})

    device = DEVICES[device_name]
    result = {
        "device": device_name,
        "host": device["host"],
        "status": "unknown",
        "uptime": None,
        "memory": {},
        "disk": {},
        "network": {}
    }

    try:
        async with get_linux_connection(device_name) as conn:
            hostname_resp = await conn.send_command("hostname")
            result["hostname"] = hostname_resp.result.strip()

            uptime_resp = await conn.send_command("uptime -p 2>/dev/null || uptime")
            result["uptime"] = uptime_resp.result.strip()

            mem_resp = await conn.send_command("free -m 2>/dev/null || cat /proc/meminfo | head -3")
            result["memory"]["raw"] = mem_resp.result

            disk_resp = await conn.send_command("df -h / 2>/dev/null | tail -1")
            result["disk"]["raw"] = disk_resp.result

            net_resp = await conn.send_command("ip addr show 2>/dev/null || ifconfig")
            result["network"]["raw"] = net_resp.result

            ping_resp = await conn.send_command("ping -c 1 -W 2 10.3.0.1 2>/dev/null && echo 'REACHABLE' || echo 'UNREACHABLE'")
            result["network"]["gateway_reachable"] = "REACHABLE" in ping_resp.result

        result["status"] = "healthy"

    except Exception as e:
        result["status"] = "critical"
        result["error"] = str(e)

    return json.dumps(result, indent=2)


async def get_cpu_memory(device_name: str) -> str:
    """Get CPU and memory utilization from a device."""
    if device_name not in DEVICES:
        return json.dumps({"error": f"Device '{device_name}' not found"})

    device = DEVICES[device_name]
    device_type = device.get("device_type", "")

    result = {
        "device": device_name,
        "cpu": {},
        "memory": {}
    }

    try:
        if device_type == "cisco_xe":
            async with get_ios_xe_connection(device_name) as conn:
                cpu_response = await conn.send_command("show processes cpu | include CPU utilization")
                cpu_output = cpu_response.result

                mem_response = await conn.send_command("show platform software status control-processor brief")
                mem_output = mem_response.result

            cpu_match = re.search(
                r'five seconds:\s*(\d+)%.*one minute:\s*(\d+)%.*five minutes:\s*(\d+)%',
                cpu_output
            )
            if cpu_match:
                result["cpu"] = {
                    "5_sec": int(cpu_match.group(1)),
                    "1_min": int(cpu_match.group(2)),
                    "5_min": int(cpu_match.group(3))
                }

            for line in mem_output.splitlines():
                if "RP0" in line or "Slot" not in line:
                    parts = line.split()
                    if len(parts) >= 6 and parts[0].startswith(("RP", "0", "R0")):
                        try:
                            result["memory"] = {
                                "used_percent": int(parts[3].replace('%', '')),
                                "committed_percent": int(parts[4].replace('%', ''))
                            }
                            break
                        except (ValueError, IndexError):
                            pass

        elif device_type == "linux":
            async with get_linux_connection(device_name) as conn:
                cpu_response = await conn.send_command("cat /proc/loadavg")
                cpu_output = cpu_response.result

                mem_response = await conn.send_command("free -m")
                mem_output = mem_response.result

            parts = cpu_output.strip().split()
            if len(parts) >= 3:
                result["cpu"] = {
                    "load_1min": float(parts[0]),
                    "load_5min": float(parts[1]),
                    "load_15min": float(parts[2])
                }

            for line in mem_output.splitlines():
                if line.startswith("Mem:"):
                    parts = line.split()
                    if len(parts) >= 3:
                        total = int(parts[1])
                        used = int(parts[2])
                        result["memory"] = {
                            "total_mb": total,
                            "used_mb": used,
                            "used_percent": round(used / total * 100, 1) if total > 0 else 0
                        }
                        break

        else:
            return json.dumps({"error": f"CPU/memory not supported for device type: {device_type}"})

        return json.dumps(result, indent=2)

    except Exception as e:
        return json.dumps({"error": str(e), "device": device_name}, indent=2)


TOOLS = [
    {"fn": linux_health_check, "name": "linux_health_check", "category": "operations"},
    {"fn": get_cpu_memory, "name": "get_cpu_memory", "category": "operations"},
]
