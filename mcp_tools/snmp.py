"""
SNMP MCP tools.

This module provides tools for SNMP operations:
- snmp_get_oid: Single OID retrieval
- snmp_walk_oid: Walk SNMP tables
- snmp_poll_metrics: Poll common device metrics
- snmp_poll_all_devices: Poll multiple devices in parallel
- snmp_list_common_oids: List common OIDs reference

Note: Convenience wrappers (snmp_get_system_info, snmp_get_interfaces) removed.
Use snmp_get_oid() with CommonOIDs or snmp_walk_oid() directly.
"""

import json

from config.devices import DEVICES
from core import log_event
from core.snmp import (
    snmp_get,
    snmp_walk,
    snmp_poll_device,
    snmp_poll_all,
    CommonOIDs,
)


# =============================================================================
# MCP Tool Functions
# =============================================================================

async def snmp_get_oid(device_name: str, oid: str) -> str:
    """
    Perform SNMP GET on a single OID.

    Use for retrieving specific values like sysUpTime, sysName, etc.
    Supports both SNMPv2c (community string) and SNMPv3 (USM).

    Args:
        device_name: Device name from inventory
        oid: OID to retrieve (e.g., "1.3.6.1.2.1.1.5.0" for sysName)

    Returns:
        JSON with OID, value, and value type

    Common OIDs:
        - 1.3.6.1.2.1.1.1.0 - sysDescr (system description)
        - 1.3.6.1.2.1.1.3.0 - sysUpTime
        - 1.3.6.1.2.1.1.5.0 - sysName
        - 1.3.6.1.2.1.1.6.0 - sysLocation
        - 1.3.6.1.2.1.2.1.0 - ifNumber (interface count)
    """
    if device_name not in DEVICES:
        return json.dumps({"error": f"Device '{device_name}' not found"})

    try:
        result = await snmp_get(device_name, oid)

        log_event("snmp_get", device_name, f"OID: {oid}", "success" if result.success else "error", "operator")

        return json.dumps({
            "device": device_name,
            "oid": result.oid,
            "value": result.value,
            "value_type": result.value_type,
            "success": result.success,
            "error": result.error,
        }, indent=2)
    except Exception as e:
        return json.dumps({"device": device_name, "error": str(e)}, indent=2)


async def snmp_walk_oid(device_name: str, oid: str, max_rows: int = 100) -> str:
    """
    Perform SNMP WALK starting from an OID.

    Use for retrieving tables or subtrees like interface statistics.

    Args:
        device_name: Device name from inventory
        oid: Base OID to walk (e.g., "1.3.6.1.2.1.2.2.1" for ifTable)
        max_rows: Maximum number of rows to retrieve (default: 100)

    Returns:
        JSON with list of OID/value pairs

    Common OIDs for walking:
        - 1.3.6.1.2.1.2.2.1 - ifTable (interface table)
        - 1.3.6.1.2.1.31.1.1.1 - ifXTable (extended interface table)
        - 1.3.6.1.2.1.4.20.1 - ipAddrTable (IP address table)
    """
    if device_name not in DEVICES:
        return json.dumps({"error": f"Device '{device_name}' not found"})

    try:
        results = await snmp_walk(device_name, oid, max_rows)

        log_event("snmp_walk", device_name, f"Walk OID: {oid}, rows: {len(results)}", "success", "operator")

        return json.dumps({
            "device": device_name,
            "base_oid": oid,
            "count": len(results),
            "results": [
                {
                    "oid": r.oid,
                    "value": r.value,
                    "value_type": r.value_type,
                }
                for r in results if r.success
            ],
            "errors": [r.error for r in results if not r.success and r.error],
        }, indent=2)
    except Exception as e:
        return json.dumps({"device": device_name, "error": str(e)}, indent=2)


async def snmp_poll_metrics(device_name: str) -> str:
    """
    Poll common metrics from a device via SNMP.

    Retrieves system info, interface status, and (for Cisco) CPU/memory.
    Use this for quick device health checks when MDT/NETCONF isn't available.

    Note: For real-time dashboard metrics, MDT telemetry is preferred.
    SNMP polling is for ad-hoc queries and legacy device support.

    Args:
        device_name: Device name from inventory

    Returns:
        JSON with system info, interfaces, CPU, and memory metrics
    """
    if device_name not in DEVICES:
        return json.dumps({"error": f"Device '{device_name}' not found"})

    try:
        result = await snmp_poll_device(device_name)

        log_event("snmp_poll", device_name, f"Poll complete, success={result.success}", "success" if result.success else "error", "operator")

        return json.dumps({
            "device": result.device,
            "success": result.success,
            "timestamp": result.timestamp,
            "system_info": result.system_info,
            "interface_count": len(result.interfaces),
            "interfaces_up": sum(1 for i in result.interfaces if i.get("oper_status") == "up"),
            "interfaces_down": sum(1 for i in result.interfaces if i.get("oper_status") == "down"),
            "cpu": result.cpu,
            "memory": result.memory,
            "error": result.error,
        }, indent=2)
    except Exception as e:
        return json.dumps({"device": device_name, "error": str(e)}, indent=2)


async def snmp_poll_all_devices(device_names: str = "") -> str:
    """
    Poll metrics from multiple devices via SNMP in parallel.

    Use for quick status check of multiple devices when MDT isn't configured.
    Runs up to 10 concurrent polls to avoid overwhelming the network.

    Args:
        device_names: Comma-separated device names (empty = all devices)

    Returns:
        JSON with polling results for each device
    """
    try:
        if device_names:
            names = [n.strip() for n in device_names.split(",")]
            # Validate device names
            invalid = [n for n in names if n not in DEVICES]
            if invalid:
                return json.dumps({"error": f"Unknown devices: {invalid}"})
        else:
            names = None  # Poll all devices

        results = await snmp_poll_all(names, max_concurrent=10)

        summary = {
            "total": len(results),
            "successful": sum(1 for r in results if r.success),
            "failed": sum(1 for r in results if not r.success),
        }

        log_event("snmp_poll_all", "all", f"Polled {summary['total']} devices, {summary['successful']} success", "success", "operator")

        return json.dumps({
            "summary": summary,
            "devices": [
                {
                    "device": r.device,
                    "success": r.success,
                    "system_name": r.system_info.get("name", ""),
                    "uptime": r.system_info.get("uptime", ""),
                    "interface_count": len(r.interfaces),
                    "cpu_5min": r.cpu.get("5min") if r.cpu else None,
                    "memory_used_pct": r.memory.get("used_percent") if r.memory else None,
                    "error": r.error,
                }
                for r in results
            ],
        }, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)}, indent=2)


def snmp_list_common_oids() -> str:
    """
    List common SNMP OIDs for network devices.

    Returns a reference of frequently used OIDs for system info,
    interfaces, and Cisco-specific metrics.

    Returns:
        JSON with categorized OID reference
    """
    return json.dumps({
        "system": {
            "sysDescr": CommonOIDs.SYS_DESCR,
            "sysObjectID": CommonOIDs.SYS_OBJECT_ID,
            "sysUpTime": CommonOIDs.SYS_UPTIME,
            "sysContact": CommonOIDs.SYS_CONTACT,
            "sysName": CommonOIDs.SYS_NAME,
            "sysLocation": CommonOIDs.SYS_LOCATION,
        },
        "interfaces": {
            "ifNumber": CommonOIDs.IF_NUMBER,
            "ifTable": CommonOIDs.IF_TABLE,
            "ifDescr": CommonOIDs.IF_DESCR,
            "ifType": CommonOIDs.IF_TYPE,
            "ifSpeed": CommonOIDs.IF_SPEED,
            "ifAdminStatus": CommonOIDs.IF_ADMIN_STATUS,
            "ifOperStatus": CommonOIDs.IF_OPER_STATUS,
            "ifInOctets": CommonOIDs.IF_IN_OCTETS,
            "ifOutOctets": CommonOIDs.IF_OUT_OCTETS,
            "ifInErrors": CommonOIDs.IF_IN_ERRORS,
            "ifOutErrors": CommonOIDs.IF_OUT_ERRORS,
        },
        "interfaces_64bit": {
            "ifHCInOctets": CommonOIDs.IF_HC_IN_OCTETS,
            "ifHCOutOctets": CommonOIDs.IF_HC_OUT_OCTETS,
            "ifName": CommonOIDs.IF_NAME,
            "ifAlias": CommonOIDs.IF_ALIAS,
        },
        "cisco_specific": {
            "cpmCPUTotal5sec": CommonOIDs.CISCO_CPU_5SEC,
            "cpmCPUTotal1min": CommonOIDs.CISCO_CPU_1MIN,
            "cpmCPUTotal5min": CommonOIDs.CISCO_CPU_5MIN,
            "ciscoMemoryPoolUsed": CommonOIDs.CISCO_MEM_POOL_USED,
            "ciscoMemoryPoolFree": CommonOIDs.CISCO_MEM_POOL_FREE,
        },
        "host_resources": {
            "hrSystemUptime": CommonOIDs.HR_SYSTEM_UPTIME,
            "hrProcessorLoad": CommonOIDs.HR_PROCESSOR_LOAD,
            "hrStorageTable": CommonOIDs.HR_STORAGE_TABLE,
        },
        "usage_notes": {
            "get": "Use snmp_get_oid for single OID retrieval",
            "walk": "Use snmp_walk_oid for tables (add .1 suffix for table columns)",
            "poll": "Use snmp_poll_metrics for quick device health check",
        },
    }, indent=2)


# =============================================================================
# Tool Registry
# =============================================================================

TOOLS = [
    {"fn": snmp_get_oid, "name": "snmp_get_oid", "category": "snmp"},
    {"fn": snmp_walk_oid, "name": "snmp_walk_oid", "category": "snmp"},
    {"fn": snmp_poll_metrics, "name": "snmp_poll_metrics", "category": "snmp"},
    {"fn": snmp_poll_all_devices, "name": "snmp_poll_all_devices", "category": "snmp"},
    {"fn": snmp_list_common_oids, "name": "snmp_list_common_oids", "category": "snmp"},
]
