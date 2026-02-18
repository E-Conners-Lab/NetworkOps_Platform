"""
SNMP v2c/v3 polling support for NetworkOps.

Provides async SNMP operations for device monitoring and legacy device support.
Uses pysnmp for protocol implementation with asyncio integration.

Features:
- SNMPv2c (community string) and SNMPv3 (USM) authentication
- Async GET, WALK, and BULK operations
- Common OID presets for system info, interfaces, CPU, memory
- Parallel polling across multiple devices
- Automatic retry with exponential backoff

Usage:
    from core.snmp import SNMPClient, snmp_get, snmp_walk, snmp_poll_device

    # Quick GET
    result = await snmp_get("R1", "1.3.6.1.2.1.1.5.0")  # sysName

    # Walk interface table
    interfaces = await snmp_walk("R1", "1.3.6.1.2.1.2.2.1")

    # Poll common metrics
    metrics = await snmp_poll_device("R1")
"""

import asyncio
import os
from dataclasses import dataclass, field
from typing import Optional
from enum import Enum

from pysnmp.hlapi.asyncio import (
    SnmpEngine,
    CommunityData,
    UsmUserData,
    UdpTransportTarget,
    ContextData,
    ObjectType,
    ObjectIdentity,
    getCmd as get_cmd,
    nextCmd as next_cmd,
    bulkCmd as bulk_cmd,
)
from pysnmp.hlapi.auth import (
    usmHMACMD5AuthProtocol,
    usmHMACSHAAuthProtocol,
    usmHMAC128SHA224AuthProtocol,
    usmHMAC192SHA256AuthProtocol,
    usmHMAC256SHA384AuthProtocol,
    usmHMAC384SHA512AuthProtocol,
    usmDESPrivProtocol,
    usmAesCfb128Protocol,
    usmAesCfb192Protocol,
    usmAesCfb256Protocol,
    usmNoAuthProtocol,
    usmNoPrivProtocol,
)
from tenacity import retry, stop_after_attempt, wait_exponential

from config.devices import DEVICES


# =============================================================================
# Common OIDs
# =============================================================================

class CommonOIDs:
    """Standard SNMP OIDs for network devices."""

    # System MIB (1.3.6.1.2.1.1)
    SYS_DESCR = "1.3.6.1.2.1.1.1.0"
    SYS_OBJECT_ID = "1.3.6.1.2.1.1.2.0"
    SYS_UPTIME = "1.3.6.1.2.1.1.3.0"
    SYS_CONTACT = "1.3.6.1.2.1.1.4.0"
    SYS_NAME = "1.3.6.1.2.1.1.5.0"
    SYS_LOCATION = "1.3.6.1.2.1.1.6.0"

    # Interface MIB (1.3.6.1.2.1.2)
    IF_NUMBER = "1.3.6.1.2.1.2.1.0"
    IF_TABLE = "1.3.6.1.2.1.2.2.1"
    IF_INDEX = "1.3.6.1.2.1.2.2.1.1"
    IF_DESCR = "1.3.6.1.2.1.2.2.1.2"
    IF_TYPE = "1.3.6.1.2.1.2.2.1.3"
    IF_MTU = "1.3.6.1.2.1.2.2.1.4"
    IF_SPEED = "1.3.6.1.2.1.2.2.1.5"
    IF_PHYS_ADDRESS = "1.3.6.1.2.1.2.2.1.6"
    IF_ADMIN_STATUS = "1.3.6.1.2.1.2.2.1.7"
    IF_OPER_STATUS = "1.3.6.1.2.1.2.2.1.8"
    IF_IN_OCTETS = "1.3.6.1.2.1.2.2.1.10"
    IF_IN_UCAST_PKTS = "1.3.6.1.2.1.2.2.1.11"
    IF_IN_ERRORS = "1.3.6.1.2.1.2.2.1.14"
    IF_OUT_OCTETS = "1.3.6.1.2.1.2.2.1.16"
    IF_OUT_UCAST_PKTS = "1.3.6.1.2.1.2.2.1.17"
    IF_OUT_ERRORS = "1.3.6.1.2.1.2.2.1.20"

    # IF-MIB 64-bit counters (ifXTable)
    IF_HC_IN_OCTETS = "1.3.6.1.2.1.31.1.1.1.6"
    IF_HC_OUT_OCTETS = "1.3.6.1.2.1.31.1.1.1.10"
    IF_NAME = "1.3.6.1.2.1.31.1.1.1.1"
    IF_ALIAS = "1.3.6.1.2.1.31.1.1.1.18"

    # IP MIB
    IP_ADDR_TABLE = "1.3.6.1.2.1.4.20.1"

    # Cisco-specific OIDs
    CISCO_CPU_5SEC = "1.3.6.1.4.1.9.9.109.1.1.1.1.6.1"
    CISCO_CPU_1MIN = "1.3.6.1.4.1.9.9.109.1.1.1.1.7.1"
    CISCO_CPU_5MIN = "1.3.6.1.4.1.9.9.109.1.1.1.1.8.1"
    CISCO_MEM_POOL_USED = "1.3.6.1.4.1.9.9.48.1.1.1.5"
    CISCO_MEM_POOL_FREE = "1.3.6.1.4.1.9.9.48.1.1.1.6"

    # HOST-RESOURCES-MIB (Linux/generic)
    HR_SYSTEM_UPTIME = "1.3.6.1.2.1.25.1.1.0"
    HR_PROCESSOR_LOAD = "1.3.6.1.2.1.25.3.3.1.2"
    HR_STORAGE_TABLE = "1.3.6.1.2.1.25.2.3.1"


# =============================================================================
# SNMP Configuration
# =============================================================================

class SNMPVersion(Enum):
    """SNMP protocol versions."""
    V2C = "v2c"
    V3 = "v3"


class SNMPv3AuthProtocol(Enum):
    """SNMPv3 authentication protocols."""
    NONE = "none"
    MD5 = "md5"
    SHA = "sha"
    SHA224 = "sha224"
    SHA256 = "sha256"
    SHA384 = "sha384"
    SHA512 = "sha512"


class SNMPv3PrivProtocol(Enum):
    """SNMPv3 privacy (encryption) protocols."""
    NONE = "none"
    DES = "des"
    AES128 = "aes128"
    AES192 = "aes192"
    AES256 = "aes256"


@dataclass
class SNMPConfig:
    """SNMP configuration for a device."""
    host: str
    port: int = 161
    timeout: float = 5.0
    retries: int = 3

    # v2c settings
    version: SNMPVersion = SNMPVersion.V2C
    community_read: str = os.getenv("SNMP_COMMUNITY_READ", "")
    community_write: str = os.getenv("SNMP_COMMUNITY_WRITE", "")

    # v3 settings
    username: str = ""
    auth_protocol: SNMPv3AuthProtocol = SNMPv3AuthProtocol.SHA256
    auth_password: str = ""
    priv_protocol: SNMPv3PrivProtocol = SNMPv3PrivProtocol.AES128
    priv_password: str = ""

    def __post_init__(self):
        if self.version == SNMPVersion.V2C and not self.community_read:
            import logging
            logging.getLogger(__name__).warning(
                "SNMP community string not configured. "
                "Set SNMP_COMMUNITY_READ in .env for SNMP to work."
            )


@dataclass
class SNMPResult:
    """Result from an SNMP operation."""
    oid: str
    value: str
    value_type: str
    success: bool = True
    error: Optional[str] = None


@dataclass
class SNMPPollResult:
    """Result from polling a device."""
    device: str
    success: bool
    timestamp: str = ""
    system_info: dict = field(default_factory=dict)
    interfaces: list = field(default_factory=list)
    cpu: Optional[dict] = None
    memory: Optional[dict] = None
    error: Optional[str] = None


# =============================================================================
# Protocol Mapping
# =============================================================================

AUTH_PROTOCOL_MAP = {
    SNMPv3AuthProtocol.NONE: usmNoAuthProtocol,
    SNMPv3AuthProtocol.MD5: usmHMACMD5AuthProtocol,
    SNMPv3AuthProtocol.SHA: usmHMACSHAAuthProtocol,
    SNMPv3AuthProtocol.SHA224: usmHMAC128SHA224AuthProtocol,
    SNMPv3AuthProtocol.SHA256: usmHMAC192SHA256AuthProtocol,
    SNMPv3AuthProtocol.SHA384: usmHMAC256SHA384AuthProtocol,
    SNMPv3AuthProtocol.SHA512: usmHMAC384SHA512AuthProtocol,
}

PRIV_PROTOCOL_MAP = {
    SNMPv3PrivProtocol.NONE: usmNoPrivProtocol,
    SNMPv3PrivProtocol.DES: usmDESPrivProtocol,
    SNMPv3PrivProtocol.AES128: usmAesCfb128Protocol,
    SNMPv3PrivProtocol.AES192: usmAesCfb192Protocol,
    SNMPv3PrivProtocol.AES256: usmAesCfb256Protocol,
}


# =============================================================================
# SNMP Client
# =============================================================================

class SNMPClient:
    """Async SNMP client for network device polling."""

    def __init__(self, config: SNMPConfig):
        """Initialize SNMP client with configuration.

        Args:
            config: SNMP configuration for the target device
        """
        self.config = config
        self._engine = SnmpEngine()

    def _get_auth_data(self):
        """Get authentication data based on SNMP version."""
        if self.config.version == SNMPVersion.V2C:
            return CommunityData(self.config.community_read)
        else:
            # SNMPv3
            auth_proto = AUTH_PROTOCOL_MAP.get(
                self.config.auth_protocol, usmNoAuthProtocol
            )
            priv_proto = PRIV_PROTOCOL_MAP.get(
                self.config.priv_protocol, usmNoPrivProtocol
            )

            return UsmUserData(
                self.config.username,
                authKey=self.config.auth_password or None,
                privKey=self.config.priv_password or None,
                authProtocol=auth_proto,
                privProtocol=priv_proto,
            )

    def _get_transport(self):
        """Get UDP transport target."""
        return UdpTransportTarget(
            (self.config.host, self.config.port),
            timeout=self.config.timeout,
            retries=self.config.retries,
        )

    async def get(self, oid: str) -> SNMPResult:
        """Perform SNMP GET operation.

        Args:
            oid: Object identifier to retrieve

        Returns:
            SNMPResult with value or error
        """
        try:
            error_indication, error_status, error_index, var_binds = await get_cmd(
                self._engine,
                self._get_auth_data(),
                self._get_transport(),
                ContextData(),
                ObjectType(ObjectIdentity(oid)),
            )

            if error_indication:
                return SNMPResult(
                    oid=oid,
                    value="",
                    value_type="error",
                    success=False,
                    error=str(error_indication),
                )

            if error_status:
                return SNMPResult(
                    oid=oid,
                    value="",
                    value_type="error",
                    success=False,
                    error=f"{error_status.prettyPrint()} at {error_index}",
                )

            if var_binds:
                oid_str, value = var_binds[0]
                return SNMPResult(
                    oid=str(oid_str),
                    value=str(value),
                    value_type=type(value).__name__,
                    success=True,
                )

            return SNMPResult(
                oid=oid,
                value="",
                value_type="empty",
                success=False,
                error="No data returned",
            )

        except Exception as e:
            return SNMPResult(
                oid=oid,
                value="",
                value_type="error",
                success=False,
                error=str(e),
            )

    async def get_bulk(self, oids: list[str]) -> list[SNMPResult]:
        """Perform SNMP GET on multiple OIDs.

        Args:
            oids: List of OIDs to retrieve

        Returns:
            List of SNMPResult objects
        """
        results = await asyncio.gather(*[self.get(oid) for oid in oids])
        return list(results)

    async def walk(self, oid: str, max_rows: int = 100) -> list[SNMPResult]:
        """Perform SNMP WALK operation.

        Args:
            oid: Base OID to walk
            max_rows: Maximum number of rows to retrieve

        Returns:
            List of SNMPResult objects
        """
        results = []
        base_oid = oid

        try:
            async for error_indication, error_status, error_index, var_binds in next_cmd(
                self._engine,
                self._get_auth_data(),
                self._get_transport(),
                ContextData(),
                ObjectType(ObjectIdentity(oid)),
            ):
                if error_indication:
                    results.append(SNMPResult(
                        oid=oid,
                        value="",
                        value_type="error",
                        success=False,
                        error=str(error_indication),
                    ))
                    break

                if error_status:
                    results.append(SNMPResult(
                        oid=oid,
                        value="",
                        value_type="error",
                        success=False,
                        error=f"{error_status.prettyPrint()} at {error_index}",
                    ))
                    break

                for var_bind in var_binds:
                    oid_str = str(var_bind[0])

                    # Stop if we've walked past the base OID
                    if not oid_str.startswith(base_oid):
                        return results

                    results.append(SNMPResult(
                        oid=oid_str,
                        value=str(var_bind[1]),
                        value_type=type(var_bind[1]).__name__,
                        success=True,
                    ))

                    if len(results) >= max_rows:
                        return results

        except Exception as e:
            results.append(SNMPResult(
                oid=oid,
                value="",
                value_type="error",
                success=False,
                error=str(e),
            ))

        return results

    async def bulk_walk(
        self,
        oid: str,
        non_repeaters: int = 0,
        max_repetitions: int = 25,
        max_rows: int = 500,
    ) -> list[SNMPResult]:
        """Perform SNMP GETBULK operation (more efficient than walk).

        Args:
            oid: Base OID to walk
            non_repeaters: Number of scalar objects
            max_repetitions: Max rows per request
            max_rows: Maximum total rows to retrieve

        Returns:
            List of SNMPResult objects
        """
        results = []
        base_oid = oid

        try:
            async for error_indication, error_status, error_index, var_binds in bulk_cmd(
                self._engine,
                self._get_auth_data(),
                self._get_transport(),
                ContextData(),
                non_repeaters,
                max_repetitions,
                ObjectType(ObjectIdentity(oid)),
            ):
                if error_indication:
                    results.append(SNMPResult(
                        oid=oid,
                        value="",
                        value_type="error",
                        success=False,
                        error=str(error_indication),
                    ))
                    break

                if error_status:
                    results.append(SNMPResult(
                        oid=oid,
                        value="",
                        value_type="error",
                        success=False,
                        error=f"{error_status.prettyPrint()} at {error_index}",
                    ))
                    break

                for var_bind in var_binds:
                    oid_str = str(var_bind[0])

                    # Stop if we've walked past the base OID
                    if not oid_str.startswith(base_oid):
                        return results

                    results.append(SNMPResult(
                        oid=oid_str,
                        value=str(var_bind[1]),
                        value_type=type(var_bind[1]).__name__,
                        success=True,
                    ))

                    if len(results) >= max_rows:
                        return results

        except Exception as e:
            results.append(SNMPResult(
                oid=oid,
                value="",
                value_type="error",
                success=False,
                error=str(e),
            ))

        return results


# =============================================================================
# Device Configuration Helpers
# =============================================================================

def get_snmp_config(device_name: str) -> SNMPConfig:
    """Get SNMP configuration for a device.

    Reads from device inventory and environment variables.

    Args:
        device_name: Device name from inventory

    Returns:
        SNMPConfig for the device

    Raises:
        ValueError: If device not found
    """
    device = DEVICES.get(device_name)
    if device is None:
        raise ValueError(f"Device '{device_name}' not found in inventory")

    # Get SNMP settings from device or environment
    snmp_version = device.get("snmp_version", os.getenv("SNMP_VERSION", "v2c"))
    community = device.get(
        "snmp_community",
        os.getenv("SNMP_COMMUNITY_READ", "public")
    )

    config = SNMPConfig(
        host=device["host"],
        port=int(device.get("snmp_port", 161)),
        community_read=community,
        version=SNMPVersion.V3 if snmp_version == "v3" else SNMPVersion.V2C,
    )

    # SNMPv3 settings
    if config.version == SNMPVersion.V3:
        from config.vault_client import get_snmp_v3_credentials
        default_user, default_auth, default_priv = get_snmp_v3_credentials()
        config.username = device.get("snmp_username", default_user)
        config.auth_password = device.get("snmp_auth_password", default_auth)
        config.priv_password = device.get("snmp_priv_password", default_priv)

        auth_proto = device.get(
            "snmp_auth_protocol",
            os.getenv("SNMP_V3_AUTH_PROTOCOL", "sha256")
        )
        config.auth_protocol = SNMPv3AuthProtocol(auth_proto.lower())

        priv_proto = device.get(
            "snmp_priv_protocol",
            os.getenv("SNMP_V3_PRIV_PROTOCOL", "aes128")
        )
        config.priv_protocol = SNMPv3PrivProtocol(priv_proto.lower())

    return config


# =============================================================================
# High-Level Functions
# =============================================================================

async def snmp_get(device_name: str, oid: str) -> SNMPResult:
    """Perform SNMP GET on a device.

    Args:
        device_name: Device name from inventory
        oid: OID to retrieve

    Returns:
        SNMPResult with value or error
    """
    config = get_snmp_config(device_name)
    client = SNMPClient(config)
    return await client.get(oid)


async def snmp_get_multiple(device_name: str, oids: list[str]) -> list[SNMPResult]:
    """Perform SNMP GET on multiple OIDs.

    Args:
        device_name: Device name from inventory
        oids: List of OIDs to retrieve

    Returns:
        List of SNMPResult objects
    """
    config = get_snmp_config(device_name)
    client = SNMPClient(config)
    return await client.get_bulk(oids)


async def snmp_walk(
    device_name: str,
    oid: str,
    max_rows: int = 100,
) -> list[SNMPResult]:
    """Perform SNMP WALK on a device.

    Args:
        device_name: Device name from inventory
        oid: Base OID to walk
        max_rows: Maximum rows to retrieve

    Returns:
        List of SNMPResult objects
    """
    config = get_snmp_config(device_name)
    client = SNMPClient(config)
    return await client.walk(oid, max_rows)


async def snmp_bulk_walk(
    device_name: str,
    oid: str,
    max_rows: int = 500,
) -> list[SNMPResult]:
    """Perform SNMP GETBULK on a device (more efficient than walk).

    Args:
        device_name: Device name from inventory
        oid: Base OID to walk
        max_rows: Maximum rows to retrieve

    Returns:
        List of SNMPResult objects
    """
    config = get_snmp_config(device_name)
    client = SNMPClient(config)
    return await client.bulk_walk(oid, max_rows=max_rows)


async def snmp_poll_device(device_name: str) -> SNMPPollResult:
    """Poll common metrics from a device.

    Retrieves system info, interface status, and (for Cisco) CPU/memory.

    Args:
        device_name: Device name from inventory

    Returns:
        SNMPPollResult with collected metrics
    """
    from core.timestamps import isonow

    device = DEVICES.get(device_name)
    if device is None:
        return SNMPPollResult(
            device=device_name,
            success=False,
            error=f"Device '{device_name}' not found",
        )

    try:
        config = get_snmp_config(device_name)
        client = SNMPClient(config)

        # Get system info
        sys_oids = [
            CommonOIDs.SYS_NAME,
            CommonOIDs.SYS_DESCR,
            CommonOIDs.SYS_UPTIME,
            CommonOIDs.SYS_LOCATION,
        ]
        sys_results = await client.get_bulk(sys_oids)

        system_info = {}
        for result in sys_results:
            if result.success:
                if CommonOIDs.SYS_NAME in result.oid:
                    system_info["name"] = result.value
                elif CommonOIDs.SYS_DESCR in result.oid:
                    system_info["description"] = result.value
                elif CommonOIDs.SYS_UPTIME in result.oid:
                    # Convert timeticks to readable format
                    try:
                        ticks = int(result.value)
                        seconds = ticks // 100
                        days = seconds // 86400
                        hours = (seconds % 86400) // 3600
                        mins = (seconds % 3600) // 60
                        system_info["uptime"] = f"{days}d {hours}h {mins}m"
                        system_info["uptime_seconds"] = seconds
                    except (ValueError, TypeError):
                        system_info["uptime"] = result.value
                elif CommonOIDs.SYS_LOCATION in result.oid:
                    system_info["location"] = result.value

        # Get interface count
        if_count_result = await client.get(CommonOIDs.IF_NUMBER)
        interface_count = 0
        if if_count_result.success:
            try:
                interface_count = int(if_count_result.value)
            except (ValueError, TypeError):
                pass

        # Get interface names and status
        interfaces = []
        if interface_count > 0:
            # Walk interface descriptions and status
            if_descr_results = await client.bulk_walk(
                CommonOIDs.IF_DESCR,
                max_rows=interface_count + 10,
            )
            if_oper_results = await client.bulk_walk(
                CommonOIDs.IF_OPER_STATUS,
                max_rows=interface_count + 10,
            )
            if_admin_results = await client.bulk_walk(
                CommonOIDs.IF_ADMIN_STATUS,
                max_rows=interface_count + 10,
            )

            # Build interface dict
            if_descr_map = {r.oid.split(".")[-1]: r.value for r in if_descr_results if r.success}
            if_oper_map = {r.oid.split(".")[-1]: r.value for r in if_oper_results if r.success}
            if_admin_map = {r.oid.split(".")[-1]: r.value for r in if_admin_results if r.success}

            for if_index, descr in if_descr_map.items():
                oper_status = if_oper_map.get(if_index, "0")
                admin_status = if_admin_map.get(if_index, "0")

                # 1=up, 2=down, 3=testing
                oper_str = "up" if oper_status == "1" else "down"
                admin_str = "up" if admin_status == "1" else "down"

                interfaces.append({
                    "index": if_index,
                    "name": descr,
                    "admin_status": admin_str,
                    "oper_status": oper_str,
                })

        # Get Cisco CPU/Memory (if applicable)
        cpu_result = None
        memory_result = None
        device_type = device.get("device_type", "")

        if "cisco" in device_type.lower():
            # CPU utilization
            cpu_results = await client.get_bulk([
                CommonOIDs.CISCO_CPU_5SEC,
                CommonOIDs.CISCO_CPU_1MIN,
                CommonOIDs.CISCO_CPU_5MIN,
            ])

            cpu_values = {}
            for result in cpu_results:
                if result.success:
                    try:
                        if "6.1" in result.oid:
                            cpu_values["5sec"] = int(result.value)
                        elif "7.1" in result.oid:
                            cpu_values["1min"] = int(result.value)
                        elif "8.1" in result.oid:
                            cpu_values["5min"] = int(result.value)
                    except (ValueError, TypeError):
                        pass

            if cpu_values:
                cpu_result = cpu_values

            # Memory utilization
            mem_used_results = await client.walk(CommonOIDs.CISCO_MEM_POOL_USED, max_rows=5)
            mem_free_results = await client.walk(CommonOIDs.CISCO_MEM_POOL_FREE, max_rows=5)

            if mem_used_results and mem_free_results:
                try:
                    # Sum up all memory pools
                    total_used = sum(
                        int(r.value) for r in mem_used_results
                        if r.success and r.value.isdigit()
                    )
                    total_free = sum(
                        int(r.value) for r in mem_free_results
                        if r.success and r.value.isdigit()
                    )
                    total = total_used + total_free
                    if total > 0:
                        memory_result = {
                            "used_bytes": total_used,
                            "free_bytes": total_free,
                            "total_bytes": total,
                            "used_percent": round((total_used / total) * 100, 1),
                        }
                except (ValueError, TypeError):
                    pass

        return SNMPPollResult(
            device=device_name,
            success=True,
            timestamp=isonow(),
            system_info=system_info,
            interfaces=interfaces,
            cpu=cpu_result,
            memory=memory_result,
        )

    except Exception as e:
        return SNMPPollResult(
            device=device_name,
            success=False,
            error=str(e),
        )


async def snmp_poll_all(
    device_names: Optional[list[str]] = None,
    max_concurrent: int = 10,
) -> list[SNMPPollResult]:
    """Poll multiple devices in parallel.

    Args:
        device_names: List of device names (None = all devices)
        max_concurrent: Maximum concurrent polls

    Returns:
        List of SNMPPollResult objects
    """
    if device_names is None:
        device_names = list(DEVICES.keys())

    semaphore = asyncio.Semaphore(max_concurrent)

    async def poll_with_semaphore(name: str) -> SNMPPollResult:
        async with semaphore:
            return await snmp_poll_device(name)

    results = await asyncio.gather(
        *[poll_with_semaphore(name) for name in device_names]
    )
    return list(results)


# =============================================================================
# Utility Functions
# =============================================================================

def format_uptime(timeticks: int) -> str:
    """Convert SNMP timeticks to human-readable format.

    Args:
        timeticks: Time in hundredths of seconds

    Returns:
        Formatted string like "5d 3h 20m"
    """
    seconds = timeticks // 100
    days = seconds // 86400
    hours = (seconds % 86400) // 3600
    mins = (seconds % 3600) // 60
    return f"{days}d {hours}h {mins}m"


def parse_interface_status(status_code: str) -> str:
    """Convert SNMP interface status code to string.

    Args:
        status_code: SNMP status (1=up, 2=down, 3=testing, etc.)

    Returns:
        Status string
    """
    status_map = {
        "1": "up",
        "2": "down",
        "3": "testing",
        "4": "unknown",
        "5": "dormant",
        "6": "notPresent",
        "7": "lowerLayerDown",
    }
    return status_map.get(str(status_code), "unknown")
