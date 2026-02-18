"""
Subnet Calculator

Provides IPv4 and IPv6 subnet calculations including:
- Network/broadcast addresses
- Usable host range
- Wildcard mask
- Binary representation
- CIDR notation conversion
"""

import ipaddress
from dataclasses import dataclass
from typing import Optional, List, Dict, Any


@dataclass
class SubnetInfo:
    """Complete subnet information."""
    # Input
    input_address: str

    # Network details
    network_address: str
    broadcast_address: str
    netmask: str
    wildcard_mask: str
    cidr_notation: str
    prefix_length: int

    # Host information
    first_usable: str
    last_usable: str
    total_hosts: int
    usable_hosts: int

    # Binary representation
    network_binary: str
    netmask_binary: str

    # Additional info
    ip_version: int
    is_private: bool
    network_class: Optional[str]  # Only for IPv4

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "input": self.input_address,
            "network": {
                "address": self.network_address,
                "broadcast": self.broadcast_address,
                "netmask": self.netmask,
                "wildcard_mask": self.wildcard_mask,
                "cidr": self.cidr_notation,
                "prefix_length": self.prefix_length,
            },
            "hosts": {
                "first_usable": self.first_usable,
                "last_usable": self.last_usable,
                "total_addresses": self.total_hosts,
                "usable_hosts": self.usable_hosts,
            },
            "binary": {
                "network": self.network_binary,
                "netmask": self.netmask_binary,
            },
            "info": {
                "ip_version": self.ip_version,
                "is_private": self.is_private,
                "network_class": self.network_class,
            },
        }


def ip_to_binary(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> str:
    """Convert IP address to binary string with dots/colons."""
    if isinstance(ip, ipaddress.IPv4Address):
        # Format as 4 octets with dots
        binary = format(int(ip), '032b')
        return '.'.join(binary[i:i+8] for i in range(0, 32, 8))
    else:
        # Format as 8 groups with colons (abbreviated)
        binary = format(int(ip), '0128b')
        return ':'.join(binary[i:i+16] for i in range(0, 128, 16))


def get_network_class(ip: ipaddress.IPv4Address) -> str:
    """Determine the classful network class for IPv4."""
    first_octet = int(ip) >> 24
    if first_octet < 128:
        return "A"
    elif first_octet < 192:
        return "B"
    elif first_octet < 224:
        return "C"
    elif first_octet < 240:
        return "D (Multicast)"
    else:
        return "E (Reserved)"


def calculate_subnet(address: str, netmask: Optional[str] = None) -> SubnetInfo:
    """
    Calculate subnet information from an IP address.

    Args:
        address: IP address in CIDR notation (e.g., "192.168.1.0/24")
                 or plain IP (e.g., "192.168.1.100")
        netmask: Optional netmask if not using CIDR notation
                 (e.g., "255.255.255.0")

    Returns:
        SubnetInfo with complete subnet details

    Raises:
        ValueError: If the address or netmask is invalid
    """
    # Parse the network
    if netmask:
        # Convert dotted decimal netmask to prefix length
        try:
            mask_obj = ipaddress.IPv4Address(netmask)
            prefix_len = bin(int(mask_obj)).count('1')
            network = ipaddress.ip_network(f"{address}/{prefix_len}", strict=False)
        except ipaddress.AddressValueError:
            raise ValueError(f"Invalid netmask: {netmask}")
    elif '/' in address:
        network = ipaddress.ip_network(address, strict=False)
    else:
        # Default to /32 for IPv4 or /128 for IPv6
        try:
            ip = ipaddress.ip_address(address)
            if ip.version == 4:
                network = ipaddress.ip_network(f"{address}/32", strict=False)
            else:
                network = ipaddress.ip_network(f"{address}/128", strict=False)
        except ValueError:
            raise ValueError(f"Invalid IP address: {address}")

    # Calculate subnet info
    if network.version == 4:
        return _calculate_ipv4_subnet(network, address)
    else:
        return _calculate_ipv6_subnet(network, address)


def _calculate_ipv4_subnet(
    network: ipaddress.IPv4Network,
    original_input: str
) -> SubnetInfo:
    """Calculate IPv4 subnet details."""
    # Get addresses
    network_addr = network.network_address
    broadcast_addr = network.broadcast_address
    netmask = network.netmask

    # Calculate wildcard mask
    wildcard = ipaddress.IPv4Address(int(netmask) ^ 0xFFFFFFFF)

    # Calculate usable hosts
    total_hosts = network.num_addresses
    if network.prefixlen == 32:
        first_usable = last_usable = str(network_addr)
        usable_hosts = 1
    elif network.prefixlen == 31:
        # Point-to-point link (RFC 3021)
        first_usable = str(network_addr)
        last_usable = str(broadcast_addr)
        usable_hosts = 2
    else:
        first_usable = str(network_addr + 1)
        last_usable = str(broadcast_addr - 1)
        usable_hosts = total_hosts - 2

    return SubnetInfo(
        input_address=original_input,
        network_address=str(network_addr),
        broadcast_address=str(broadcast_addr),
        netmask=str(netmask),
        wildcard_mask=str(wildcard),
        cidr_notation=str(network),
        prefix_length=network.prefixlen,
        first_usable=first_usable,
        last_usable=last_usable,
        total_hosts=total_hosts,
        usable_hosts=usable_hosts,
        network_binary=ip_to_binary(network_addr),
        netmask_binary=ip_to_binary(netmask),
        ip_version=4,
        is_private=network.is_private,
        network_class=get_network_class(network_addr),
    )


def _calculate_ipv6_subnet(
    network: ipaddress.IPv6Network,
    original_input: str
) -> SubnetInfo:
    """Calculate IPv6 subnet details."""
    network_addr = network.network_address
    broadcast_addr = network.broadcast_address  # Last address in range

    # IPv6 doesn't have traditional netmask, but we can represent it
    netmask = network.netmask

    # Calculate "wildcard" (hostmask)
    hostmask = network.hostmask

    # Calculate hosts (can be astronomical for IPv6)
    total_hosts = network.num_addresses

    if network.prefixlen == 128:
        first_usable = last_usable = str(network_addr)
        usable_hosts = 1
    elif network.prefixlen == 127:
        # Point-to-point (RFC 6164)
        first_usable = str(network_addr)
        last_usable = str(broadcast_addr)
        usable_hosts = 2
    else:
        first_usable = str(network_addr + 1)
        last_usable = str(broadcast_addr - 1)
        usable_hosts = total_hosts - 2

    return SubnetInfo(
        input_address=original_input,
        network_address=str(network_addr),
        broadcast_address=str(broadcast_addr),
        netmask=str(netmask),
        wildcard_mask=str(hostmask),
        cidr_notation=str(network),
        prefix_length=network.prefixlen,
        first_usable=first_usable,
        last_usable=last_usable,
        total_hosts=total_hosts,
        usable_hosts=usable_hosts,
        network_binary=ip_to_binary(network_addr),
        netmask_binary=ip_to_binary(netmask),
        ip_version=6,
        is_private=network.is_private,
        network_class=None,  # No classes in IPv6
    )


def cidr_to_netmask(prefix_length: int, version: int = 4) -> str:
    """Convert CIDR prefix length to netmask."""
    if version == 4:
        if not 0 <= prefix_length <= 32:
            raise ValueError(f"Invalid IPv4 prefix length: {prefix_length}")
        mask = (0xFFFFFFFF << (32 - prefix_length)) & 0xFFFFFFFF
        return str(ipaddress.IPv4Address(mask))
    else:
        if not 0 <= prefix_length <= 128:
            raise ValueError(f"Invalid IPv6 prefix length: {prefix_length}")
        mask = (((1 << 128) - 1) << (128 - prefix_length)) & ((1 << 128) - 1)
        return str(ipaddress.IPv6Address(mask))


def netmask_to_cidr(netmask: str) -> int:
    """Convert netmask to CIDR prefix length."""
    try:
        mask = ipaddress.IPv4Address(netmask)
        binary = bin(int(mask))
        # Valid netmask must be contiguous 1s followed by 0s
        if '01' in binary:
            raise ValueError(f"Invalid netmask: {netmask}")
        return binary.count('1')
    except ipaddress.AddressValueError:
        raise ValueError(f"Invalid netmask: {netmask}")


def get_common_subnets() -> List[Dict[str, Any]]:
    """Return a reference table of common subnet sizes."""
    return [
        {"prefix": 32, "netmask": "255.255.255.255", "hosts": 1, "description": "Host route"},
        {"prefix": 31, "netmask": "255.255.255.254", "hosts": 2, "description": "Point-to-point link (RFC 3021)"},
        {"prefix": 30, "netmask": "255.255.255.252", "hosts": 2, "description": "Point-to-point link (traditional)"},
        {"prefix": 29, "netmask": "255.255.255.248", "hosts": 6, "description": "Small subnet"},
        {"prefix": 28, "netmask": "255.255.255.240", "hosts": 14, "description": "Small subnet"},
        {"prefix": 27, "netmask": "255.255.255.224", "hosts": 30, "description": "Small subnet"},
        {"prefix": 26, "netmask": "255.255.255.192", "hosts": 62, "description": "Medium subnet"},
        {"prefix": 25, "netmask": "255.255.255.128", "hosts": 126, "description": "Medium subnet"},
        {"prefix": 24, "netmask": "255.255.255.0", "hosts": 254, "description": "Class C / Standard LAN"},
        {"prefix": 23, "netmask": "255.255.254.0", "hosts": 510, "description": "2x Class C"},
        {"prefix": 22, "netmask": "255.255.252.0", "hosts": 1022, "description": "4x Class C"},
        {"prefix": 21, "netmask": "255.255.248.0", "hosts": 2046, "description": "8x Class C"},
        {"prefix": 20, "netmask": "255.255.240.0", "hosts": 4094, "description": "16x Class C"},
        {"prefix": 16, "netmask": "255.255.0.0", "hosts": 65534, "description": "Class B"},
        {"prefix": 8, "netmask": "255.0.0.0", "hosts": 16777214, "description": "Class A"},
    ]


def split_subnet(
    network: str,
    new_prefix: int
) -> List[Dict[str, str]]:
    """
    Split a network into smaller subnets.

    Args:
        network: Network in CIDR notation (e.g., "192.168.1.0/24")
        new_prefix: New prefix length for subnets (must be larger than original)

    Returns:
        List of subnet dictionaries with network, first/last usable, broadcast
    """
    net = ipaddress.ip_network(network, strict=False)

    if new_prefix <= net.prefixlen:
        raise ValueError(f"New prefix {new_prefix} must be larger than original {net.prefixlen}")

    if net.version == 4 and new_prefix > 32:
        raise ValueError(f"Invalid IPv4 prefix: {new_prefix}")
    elif net.version == 6 and new_prefix > 128:
        raise ValueError(f"Invalid IPv6 prefix: {new_prefix}")

    subnets = []
    for subnet in net.subnets(new_prefix=new_prefix):
        if subnet.version == 4:
            if subnet.prefixlen >= 31:
                first = str(subnet.network_address)
                last = str(subnet.broadcast_address)
            else:
                first = str(subnet.network_address + 1)
                last = str(subnet.broadcast_address - 1)
        else:
            if subnet.prefixlen >= 127:
                first = str(subnet.network_address)
                last = str(subnet.broadcast_address)
            else:
                first = str(subnet.network_address + 1)
                last = str(subnet.broadcast_address - 1)

        subnets.append({
            "network": str(subnet),
            "first_usable": first,
            "last_usable": last,
            "broadcast": str(subnet.broadcast_address),
            "hosts": subnet.num_addresses - 2 if subnet.prefixlen < 31 else subnet.num_addresses,
        })

    return subnets
