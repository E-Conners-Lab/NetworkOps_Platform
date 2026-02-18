"""
Calculator MCP tools.

Pure calculation tools with no network dependencies:
- calculate_tunnel_mtu: Calculate optimal MTU/MSS for VPN tunnels
- get_mtu_scenarios: Pre-calculated MTU values for common scenarios
- calculate_subnet_info: Calculate subnet details from IP address
- split_network: Split network into smaller subnets (VLSM)
- get_subnet_reference: Reference table of common subnet sizes
- convert_netmask: Convert between CIDR prefix and dotted decimal
"""

import json


# =============================================================================
# MTU/MSS Calculator Tools
# =============================================================================

async def calculate_tunnel_mtu(
    tunnel_type: str,
    physical_mtu: int = 1500,
    encryption: str = None,
    auth: str = None,
    nat_traversal: bool = False,
    platform: str = None,
    interface: str = "Tunnel0",
) -> str:
    """
    Calculate optimal tunnel MTU and TCP MSS for VPN tunnels.

    Solves the "silent killer" of VPNs—fragmentation. When tunnel headers
    cause packets to exceed the physical MTU, packets get fragmented or dropped.

    Args:
        tunnel_type: Tunnel encapsulation type:
            - "gre": Pure GRE (no encryption)
            - "gre_ipsec": GRE over IPsec (DMVPN)
            - "ipsec_tunnel": Pure IPsec tunnel mode
            - "ipsec_transport": IPsec transport mode
            - "vxlan": VXLAN overlay
            - "wireguard": WireGuard VPN
        physical_mtu: Physical interface MTU (default: 1500)
        encryption: IPsec encryption algorithm:
            - "aes-256-gcm" (default, recommended)
            - "aes-128-gcm"
            - "aes-256-cbc"
            - "aes-128-cbc"
            - "chacha20-poly1305"
        auth: IPsec authentication algorithm (auto-selected for GCM modes):
            - "sha256" (default for CBC)
            - "sha384", "sha512"
            - "sha1" (legacy)
        nat_traversal: Whether NAT-T (UDP encapsulation) is used
        platform: Generate config for platform (optional):
            - "cisco_ios", "cisco_iosxe", "cisco_asa"
            - "juniper_junos"
            - "palo_alto"
            - "fortinet"
            - "linux"
        interface: Interface name for config output (default: Tunnel0)

    Returns:
        JSON with calculated MTU/MSS values, overhead breakdown, and optional config

    Examples:
        calculate_tunnel_mtu("gre_ipsec")  # DMVPN defaults
        calculate_tunnel_mtu("gre_ipsec", nat_traversal=True)  # With NAT-T
        calculate_tunnel_mtu("ipsec_tunnel", encryption="aes-256-cbc", auth="sha256")
        calculate_tunnel_mtu("gre_ipsec", platform="cisco_ios", interface="Tunnel100")
    """
    from core.mtu_calculator import (
        TunnelType, EncryptionAlgorithm, AuthAlgorithm, Platform,
        calculate_mtu, generate_config
    )

    # Map string inputs to enums
    tunnel_type_map = {
        "gre": TunnelType.GRE,
        "gre_ipsec": TunnelType.GRE_IPSEC,
        "ipsec_tunnel": TunnelType.IPSEC_TUNNEL,
        "ipsec_transport": TunnelType.IPSEC_TRANSPORT,
        "vxlan": TunnelType.VXLAN,
        "geneve": TunnelType.GENEVE,
        "wireguard": TunnelType.WIREGUARD,
    }

    encryption_map = {
        "aes-128-cbc": EncryptionAlgorithm.AES_128_CBC,
        "aes-256-cbc": EncryptionAlgorithm.AES_256_CBC,
        "aes-128-gcm": EncryptionAlgorithm.AES_128_GCM,
        "aes-256-gcm": EncryptionAlgorithm.AES_256_GCM,
        "des-cbc": EncryptionAlgorithm.DES_CBC,
        "3des-cbc": EncryptionAlgorithm.THREE_DES_CBC,
        "chacha20-poly1305": EncryptionAlgorithm.CHACHA20_POLY1305,
    }

    auth_map = {
        "sha1": AuthAlgorithm.SHA1,
        "sha256": AuthAlgorithm.SHA256,
        "sha384": AuthAlgorithm.SHA384,
        "sha512": AuthAlgorithm.SHA512,
        "md5": AuthAlgorithm.MD5,
        "gcm": AuthAlgorithm.GCM,
    }

    platform_map = {
        "cisco_ios": Platform.CISCO_IOS,
        "cisco_iosxe": Platform.CISCO_IOSXE,
        "cisco_asa": Platform.CISCO_ASA,
        "cisco_nxos": Platform.CISCO_NXOS,
        "juniper_junos": Platform.JUNIPER_JUNOS,
        "palo_alto": Platform.PALO_ALTO,
        "fortinet": Platform.FORTINET,
        "linux": Platform.LINUX,
        "nokia_srlinux": Platform.NOKIA_SRLINUX,
        "nokia_sros": Platform.NOKIA_SROS,
        "arista_eos": Platform.ARISTA_EOS,
        "mikrotik": Platform.MIKROTIK,
        "huawei_vrp": Platform.HUAWEI_VRP,
        "vyos": Platform.VYOS,
    }

    # Validate tunnel type
    if tunnel_type.lower() not in tunnel_type_map:
        return json.dumps({
            "error": f"Unknown tunnel type: {tunnel_type}",
            "valid_types": list(tunnel_type_map.keys())
        }, indent=2)

    # Convert inputs
    tt = tunnel_type_map[tunnel_type.lower()]
    enc = encryption_map.get(encryption.lower()) if encryption else None
    au = auth_map.get(auth.lower()) if auth else None
    plat = platform_map.get(platform.lower()) if platform else None

    # Calculate MTU
    try:
        result = calculate_mtu(
            tunnel_type=tt,
            physical_mtu=physical_mtu,
            encryption=enc,
            auth=au,
            nat_traversal=nat_traversal,
        )
    except Exception as e:
        return json.dumps({"error": str(e)}, indent=2)

    # Build response
    response = result.to_dict()

    # Add config if platform specified
    if plat:
        response["config"] = generate_config(result, plat, interface)
        response["platform"] = platform

    return json.dumps(response, indent=2)


async def get_mtu_scenarios() -> str:
    """
    Get pre-calculated MTU/MSS values for common tunnel scenarios.

    Returns recommended settings for:
    - DMVPN Phase 3 (AES-256-GCM)
    - DMVPN with NAT-T
    - Site-to-Site IPsec (AES-256-CBC)
    - Pure GRE (no encryption)
    - VXLAN
    - WireGuard

    All calculations assume 1500 byte physical MTU.

    Returns:
        JSON with tunnel_mtu, tcp_mss, and overhead for each scenario
    """
    from core.mtu_calculator import get_common_scenarios

    scenarios = get_common_scenarios()

    return json.dumps({
        "physical_mtu": 1500,
        "scenarios": scenarios,
        "note": "Use calculate_tunnel_mtu() for custom parameters"
    }, indent=2)


# =============================================================================
# Subnet Calculator Tools
# =============================================================================

async def calculate_subnet_info(
    address: str,
    netmask: str = None,
) -> str:
    """
    Calculate detailed subnet information from an IP address.

    Args:
        address: IP address in CIDR notation (e.g., "192.168.1.0/24")
                 or plain IP (e.g., "192.168.1.100")
        netmask: Optional netmask if not using CIDR notation
                 (e.g., "255.255.255.0")

    Returns:
        JSON with complete subnet details including:
        - Network address, broadcast, netmask, wildcard mask
        - First/last usable host addresses
        - Total and usable host counts
        - Binary representations
        - IP version, private/public status, network class

    Examples:
        calculate_subnet_info("192.168.1.0/24")
        calculate_subnet_info("10.0.12.1/30")
        calculate_subnet_info("192.168.1.100", "255.255.255.0")
        calculate_subnet_info("2001:db8::/32")  # IPv6
    """
    from core.subnet_calculator import calculate_subnet

    try:
        result = calculate_subnet(address, netmask)
        return json.dumps(result.to_dict(), indent=2)
    except ValueError as e:
        return json.dumps({"error": str(e)}, indent=2)


async def split_network(
    network: str,
    new_prefix: int,
) -> str:
    """
    Split a network into smaller subnets (VLSM).

    Args:
        network: Network in CIDR notation (e.g., "192.168.1.0/24")
        new_prefix: New prefix length for subnets (must be larger than original)

    Returns:
        JSON with list of subnets including network, first/last usable, hosts

    Examples:
        split_network("192.168.1.0/24", 26)  # Split /24 into four /26 subnets
        split_network("10.0.0.0/16", 24)     # Split /16 into 256 /24 subnets
    """
    from core.subnet_calculator import split_subnet

    try:
        subnets = split_subnet(network, new_prefix)
        return json.dumps({
            "original_network": network,
            "new_prefix": new_prefix,
            "subnet_count": len(subnets),
            "subnets": subnets,
        }, indent=2)
    except ValueError as e:
        return json.dumps({"error": str(e)}, indent=2)


async def get_subnet_reference() -> str:
    """
    Get a reference table of common subnet sizes.

    Returns:
        JSON with prefix lengths, netmasks, and usable hosts for common subnets
    """
    from core.subnet_calculator import get_common_subnets

    return json.dumps({
        "common_subnets": get_common_subnets(),
        "notes": {
            "hosts": "Usable host addresses (excluding network and broadcast)",
            "/31": "Point-to-point links (RFC 3021) - both addresses usable",
            "/32": "Host routes - single address",
        }
    }, indent=2)


async def convert_netmask(
    value: str,
) -> str:
    """
    Convert between CIDR prefix and dotted decimal netmask.

    Args:
        value: Either a prefix length (e.g., "24") or netmask (e.g., "255.255.255.0")

    Returns:
        JSON with both CIDR prefix and dotted decimal netmask

    Examples:
        convert_netmask("24")              # Returns /24 = 255.255.255.0
        convert_netmask("255.255.255.0")   # Returns 255.255.255.0 = /24
    """
    from core.subnet_calculator import cidr_to_netmask, netmask_to_cidr

    try:
        # Check if it's a prefix length (number)
        if value.isdigit():
            prefix = int(value)
            netmask = cidr_to_netmask(prefix)
            return json.dumps({
                "prefix_length": prefix,
                "netmask": netmask,
                "cidr": f"/{prefix}",
            }, indent=2)
        else:
            # Assume it's a netmask
            prefix = netmask_to_cidr(value)
            return json.dumps({
                "netmask": value,
                "prefix_length": prefix,
                "cidr": f"/{prefix}",
            }, indent=2)
    except ValueError as e:
        return json.dumps({"error": str(e)}, indent=2)


# =============================================================================
# Tool Registry
# =============================================================================

TOOLS = [
    {"fn": calculate_tunnel_mtu, "name": "calculate_tunnel_mtu", "category": "calculators"},
    {"fn": get_mtu_scenarios, "name": "get_mtu_scenarios", "category": "calculators"},
    {"fn": calculate_subnet_info, "name": "calculate_subnet_info", "category": "calculators"},
    {"fn": split_network, "name": "split_network", "category": "calculators"},
    {"fn": get_subnet_reference, "name": "get_subnet_reference", "category": "calculators"},
    {"fn": convert_netmask, "name": "convert_netmask", "category": "calculators"},
]
