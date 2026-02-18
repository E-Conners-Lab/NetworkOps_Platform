"""
Tunnel MTU & MSS Calculator

Solves the "silent killer" of VPNs—fragmentation.

When tunnel headers cause packets to exceed the physical MTU, packets get fragmented
or dropped (especially with DF bit set). This calculator determines the correct:
- Tunnel interface MTU
- TCP MSS (Maximum Segment Size) for ip tcp adjust-mss

Overhead Reference:
- IP header: 20 bytes (no options)
- GRE header: 4 bytes (8 with key/sequence)
- IPsec ESP header: 8 bytes
- IPsec ESP trailer: 2 bytes + padding (up to block size)
- IPsec ESP auth: 12-32 bytes depending on algorithm
- IPsec ESP IV: 8-16 bytes depending on algorithm
- New outer IP header (tunnel mode): 20 bytes
- UDP header (NAT-T): 8 bytes
- VXLAN header: 8 bytes + UDP 8 + outer IP 20 = 50 bytes total
"""

from dataclasses import dataclass
from enum import Enum
from typing import Optional


class TunnelType(Enum):
    """Supported tunnel encapsulation types."""
    GRE = "gre"
    GRE_IPSEC = "gre_ipsec"  # GRE over IPsec (common for DMVPN)
    IPSEC_TUNNEL = "ipsec_tunnel"  # Pure IPsec tunnel mode
    IPSEC_TRANSPORT = "ipsec_transport"  # IPsec transport mode
    VXLAN = "vxlan"
    GENEVE = "geneve"
    WIREGUARD = "wireguard"


class EncryptionAlgorithm(Enum):
    """IPsec encryption algorithms with their IV and block sizes."""
    AES_128_CBC = "aes-128-cbc"
    AES_256_CBC = "aes-256-cbc"
    AES_128_GCM = "aes-128-gcm"
    AES_256_GCM = "aes-256-gcm"
    DES_CBC = "des-cbc"  # Legacy
    THREE_DES_CBC = "3des-cbc"  # Legacy
    CHACHA20_POLY1305 = "chacha20-poly1305"


class AuthAlgorithm(Enum):
    """IPsec authentication algorithms with their ICV (auth tag) sizes."""
    SHA1 = "sha1"  # 12 bytes (96 bits)
    SHA256 = "sha256"  # 16 bytes (128 bits)
    SHA384 = "sha384"  # 24 bytes (192 bits)
    SHA512 = "sha512"  # 32 bytes (256 bits)
    MD5 = "md5"  # 12 bytes (96 bits) - Legacy
    GCM = "gcm"  # 16 bytes (128 bits) - Built into AES-GCM


class Platform(Enum):
    """Target platform for configuration output."""
    CISCO_IOS = "cisco_ios"
    CISCO_IOSXE = "cisco_iosxe"
    CISCO_ASA = "cisco_asa"
    CISCO_NXOS = "cisco_nxos"
    JUNIPER_JUNOS = "juniper_junos"
    PALO_ALTO = "palo_alto"
    FORTINET = "fortinet"
    LINUX = "linux"
    NOKIA_SRLINUX = "nokia_srlinux"
    NOKIA_SROS = "nokia_sros"
    ARISTA_EOS = "arista_eos"
    MIKROTIK = "mikrotik"
    HUAWEI_VRP = "huawei_vrp"
    VYOS = "vyos"


# Encryption algorithm properties: (IV size, block size)
ENCRYPTION_PROPERTIES = {
    EncryptionAlgorithm.AES_128_CBC: (16, 16),
    EncryptionAlgorithm.AES_256_CBC: (16, 16),
    EncryptionAlgorithm.AES_128_GCM: (8, 1),  # GCM uses 8-byte IV, stream cipher (no padding)
    EncryptionAlgorithm.AES_256_GCM: (8, 1),
    EncryptionAlgorithm.DES_CBC: (8, 8),
    EncryptionAlgorithm.THREE_DES_CBC: (8, 8),
    EncryptionAlgorithm.CHACHA20_POLY1305: (8, 1),  # Stream cipher
}

# Authentication ICV sizes in bytes
AUTH_ICV_SIZES = {
    AuthAlgorithm.SHA1: 12,
    AuthAlgorithm.SHA256: 16,
    AuthAlgorithm.SHA384: 24,
    AuthAlgorithm.SHA512: 32,
    AuthAlgorithm.MD5: 12,
    AuthAlgorithm.GCM: 16,  # AES-GCM has 16-byte auth tag
}


@dataclass
class OverheadBreakdown:
    """Detailed breakdown of tunnel overhead."""
    outer_ip_header: int = 0
    gre_header: int = 0
    esp_header: int = 0  # SPI + Sequence
    esp_iv: int = 0
    esp_padding: int = 0  # Worst case padding
    esp_trailer: int = 0  # Pad length + Next header
    esp_auth: int = 0  # ICV
    udp_header: int = 0  # For NAT-T or VXLAN
    vxlan_header: int = 0
    other: int = 0

    @property
    def total(self) -> int:
        return (
            self.outer_ip_header +
            self.gre_header +
            self.esp_header +
            self.esp_iv +
            self.esp_padding +
            self.esp_trailer +
            self.esp_auth +
            self.udp_header +
            self.vxlan_header +
            self.other
        )

    def to_dict(self) -> dict:
        """Return non-zero components."""
        result = {}
        if self.outer_ip_header:
            result["Outer IP Header"] = self.outer_ip_header
        if self.gre_header:
            result["GRE Header"] = self.gre_header
        if self.esp_header:
            result["ESP Header (SPI+Seq)"] = self.esp_header
        if self.esp_iv:
            result["ESP IV"] = self.esp_iv
        if self.esp_padding:
            result["ESP Padding (worst case)"] = self.esp_padding
        if self.esp_trailer:
            result["ESP Trailer"] = self.esp_trailer
        if self.esp_auth:
            result["ESP Auth (ICV)"] = self.esp_auth
        if self.udp_header:
            result["UDP Header (NAT-T)"] = self.udp_header
        if self.vxlan_header:
            result["VXLAN Header"] = self.vxlan_header
        if self.other:
            result["Other"] = self.other
        result["Total Overhead"] = self.total
        return result


@dataclass
class MTUResult:
    """Results of MTU/MSS calculation."""
    physical_mtu: int
    tunnel_mtu: int
    tcp_mss: int
    total_overhead: int
    breakdown: OverheadBreakdown
    tunnel_type: str
    encryption: Optional[str]
    nat_traversal: bool
    warnings: list[str]

    def to_dict(self) -> dict:
        return {
            "physical_mtu": self.physical_mtu,
            "tunnel_mtu": self.tunnel_mtu,
            "tcp_mss": self.tcp_mss,
            "total_overhead": self.total_overhead,
            "overhead_breakdown": self.breakdown.to_dict(),
            "tunnel_type": self.tunnel_type,
            "encryption": self.encryption,
            "nat_traversal": self.nat_traversal,
            "warnings": self.warnings,
        }


def calculate_esp_overhead(
    encryption: EncryptionAlgorithm,
    auth: AuthAlgorithm,
    tunnel_mode: bool = True,
    nat_traversal: bool = False,
) -> OverheadBreakdown:
    """
    Calculate IPsec ESP overhead.

    ESP packet format:
    [SPI (4)] [Seq (4)] [IV (8-16)] [Payload...] [Padding (0-15)] [Pad Len (1)] [Next Hdr (1)] [Auth (12-32)]

    In tunnel mode, add outer IP header (20 bytes).
    With NAT-T, add UDP header (8 bytes).
    """
    breakdown = OverheadBreakdown()

    # Outer IP header for tunnel mode
    if tunnel_mode:
        breakdown.outer_ip_header = 20

    # ESP header: SPI (4) + Sequence Number (4)
    breakdown.esp_header = 8

    # IV size depends on encryption algorithm
    iv_size, block_size = ENCRYPTION_PROPERTIES[encryption]
    breakdown.esp_iv = iv_size

    # ESP trailer: Pad Length (1) + Next Header (1)
    breakdown.esp_trailer = 2

    # Worst-case padding (block_size - 1 for CBC, 0 for stream ciphers)
    if block_size > 1:
        breakdown.esp_padding = block_size - 1

    # Authentication ICV
    breakdown.esp_auth = AUTH_ICV_SIZES[auth]

    # NAT-T adds UDP encapsulation
    if nat_traversal:
        breakdown.udp_header = 8

    return breakdown


def calculate_gre_overhead(with_key: bool = False, with_sequence: bool = False) -> int:
    """
    Calculate GRE header overhead.

    Basic GRE: 4 bytes
    With Key: +4 bytes
    With Sequence: +4 bytes
    Plus outer IP header: 20 bytes
    """
    overhead = 4  # Basic GRE header
    if with_key:
        overhead += 4
    if with_sequence:
        overhead += 4
    return overhead + 20  # Add outer IP


def calculate_mtu(
    tunnel_type: TunnelType,
    physical_mtu: int = 1500,
    encryption: Optional[EncryptionAlgorithm] = None,
    auth: Optional[AuthAlgorithm] = None,
    nat_traversal: bool = False,
    gre_key: bool = False,
    gre_sequence: bool = False,
) -> MTUResult:
    """
    Calculate optimal tunnel MTU and TCP MSS.

    Args:
        tunnel_type: Type of tunnel encapsulation
        physical_mtu: Physical interface MTU (default 1500)
        encryption: IPsec encryption algorithm (required for IPsec tunnels)
        auth: IPsec authentication algorithm (required for IPsec tunnels)
        nat_traversal: Whether NAT-T (UDP encapsulation) is used
        gre_key: Whether GRE key is configured
        gre_sequence: Whether GRE sequence numbers are enabled

    Returns:
        MTUResult with calculated values and overhead breakdown
    """
    warnings = []
    breakdown = OverheadBreakdown()

    # Set defaults for IPsec if not specified
    if tunnel_type in (TunnelType.GRE_IPSEC, TunnelType.IPSEC_TUNNEL, TunnelType.IPSEC_TRANSPORT):
        if encryption is None:
            encryption = EncryptionAlgorithm.AES_256_GCM
            warnings.append(f"Using default encryption: {encryption.value}")
        if auth is None:
            # GCM modes have built-in auth
            if "gcm" in encryption.value:
                auth = AuthAlgorithm.GCM
            else:
                auth = AuthAlgorithm.SHA256
                warnings.append(f"Using default authentication: {auth.value}")

    # Calculate overhead based on tunnel type
    if tunnel_type == TunnelType.GRE:
        # Pure GRE (no encryption)
        gre_overhead = calculate_gre_overhead(gre_key, gre_sequence)
        breakdown.outer_ip_header = 20
        breakdown.gre_header = gre_overhead - 20  # Subtract IP header already counted

    elif tunnel_type == TunnelType.GRE_IPSEC:
        # GRE over IPsec (DMVPN typical config)
        # Order: [Outer IP] [ESP Header] [GRE] [Inner IP] [Payload]
        gre_overhead = calculate_gre_overhead(gre_key, gre_sequence)
        esp_breakdown = calculate_esp_overhead(encryption, auth, tunnel_mode=True, nat_traversal=nat_traversal)

        breakdown = esp_breakdown
        breakdown.gre_header = gre_overhead - 20  # GRE without its IP header (ESP provides outer IP)

    elif tunnel_type == TunnelType.IPSEC_TUNNEL:
        # Pure IPsec tunnel mode
        breakdown = calculate_esp_overhead(encryption, auth, tunnel_mode=True, nat_traversal=nat_traversal)

    elif tunnel_type == TunnelType.IPSEC_TRANSPORT:
        # IPsec transport mode (no outer IP header)
        breakdown = calculate_esp_overhead(encryption, auth, tunnel_mode=False, nat_traversal=nat_traversal)

    elif tunnel_type == TunnelType.VXLAN:
        # VXLAN: Outer IP (20) + UDP (8) + VXLAN (8) = 50 bytes
        breakdown.outer_ip_header = 20
        breakdown.udp_header = 8
        breakdown.vxlan_header = 8

    elif tunnel_type == TunnelType.GENEVE:
        # GENEVE: Outer IP (20) + UDP (8) + GENEVE base (8) + options (variable, assume 0)
        breakdown.outer_ip_header = 20
        breakdown.udp_header = 8
        breakdown.other = 8  # GENEVE base header

    elif tunnel_type == TunnelType.WIREGUARD:
        # WireGuard: Outer IP (20) + UDP (8) + WG header (32) + Auth tag (16)
        breakdown.outer_ip_header = 20
        breakdown.udp_header = 8
        breakdown.other = 32 + 16  # WG transport header + auth tag

    total_overhead = breakdown.total
    tunnel_mtu = physical_mtu - total_overhead

    # TCP MSS = MTU - IP header (20) - TCP header (20)
    tcp_mss = tunnel_mtu - 40

    # Sanity checks
    if tunnel_mtu < 576:  # Minimum IPv4 MTU
        warnings.append(f"WARNING: Calculated tunnel MTU ({tunnel_mtu}) is below IPv4 minimum (576)")
    if tunnel_mtu < 1280:  # Minimum IPv6 MTU
        warnings.append(f"WARNING: Calculated tunnel MTU ({tunnel_mtu}) is below IPv6 minimum (1280)")
    if tcp_mss < 536:  # Minimum TCP MSS
        warnings.append(f"WARNING: Calculated TCP MSS ({tcp_mss}) is below recommended minimum (536)")

    # Common issues
    if nat_traversal and tunnel_type not in (TunnelType.GRE_IPSEC, TunnelType.IPSEC_TUNNEL, TunnelType.IPSEC_TRANSPORT):
        warnings.append("NAT-T is only applicable to IPsec tunnels")

    return MTUResult(
        physical_mtu=physical_mtu,
        tunnel_mtu=tunnel_mtu,
        tcp_mss=tcp_mss,
        total_overhead=total_overhead,
        breakdown=breakdown,
        tunnel_type=tunnel_type.value,
        encryption=encryption.value if encryption else None,
        nat_traversal=nat_traversal,
        warnings=warnings,
    )


def generate_config(result: MTUResult, platform: Platform, interface: str = "Tunnel0") -> str:
    """
    Generate platform-specific configuration commands.

    Args:
        result: MTUResult from calculate_mtu()
        platform: Target platform
        interface: Interface name (default: Tunnel0)

    Returns:
        Configuration snippet as string
    """
    configs = []

    if platform in (Platform.CISCO_IOS, Platform.CISCO_IOSXE):
        configs.append(f"! Tunnel MTU and MSS configuration for {interface}")
        configs.append(f"! Physical MTU: {result.physical_mtu}, Overhead: {result.total_overhead} bytes")
        configs.append(f"interface {interface}")
        configs.append(f" ip mtu {result.tunnel_mtu}")
        configs.append(f" ip tcp adjust-mss {result.tcp_mss}")
        if result.tunnel_mtu < 1400:
            configs.append(" ! Consider: ip ospf mtu-ignore (if OSPF over tunnel)")

    elif platform == Platform.CISCO_ASA:
        configs.append(f"! Tunnel MTU configuration")
        configs.append(f"! Physical MTU: {result.physical_mtu}, Overhead: {result.total_overhead} bytes")
        configs.append(f"mtu {interface} {result.tunnel_mtu}")
        configs.append(f"sysopt connection tcpmss {result.tcp_mss}")

    elif platform == Platform.JUNIPER_JUNOS:
        configs.append(f"# Tunnel MTU and MSS configuration for {interface}")
        configs.append(f"# Physical MTU: {result.physical_mtu}, Overhead: {result.total_overhead} bytes")
        configs.append(f"set interfaces {interface} mtu {result.tunnel_mtu}")
        configs.append(f"set security flow tcp-mss ipsec-vpn mss {result.tcp_mss}")

    elif platform == Platform.PALO_ALTO:
        configs.append(f"# Tunnel MTU configuration")
        configs.append(f"# Physical MTU: {result.physical_mtu}, Overhead: {result.total_overhead} bytes")
        configs.append(f"set network interface tunnel units {interface} mtu {result.tunnel_mtu}")
        configs.append(f"# For IPSec: set network ipsec ipsec-crypto-profile <profile> esp-override-mss enable")
        configs.append(f"# MSS value: {result.tcp_mss}")

    elif platform == Platform.FORTINET:
        configs.append(f"# Tunnel MTU and MSS configuration")
        configs.append(f"# Physical MTU: {result.physical_mtu}, Overhead: {result.total_overhead} bytes")
        configs.append(f"config vpn ipsec phase1-interface")
        configs.append(f"    edit \"{interface}\"")
        configs.append(f"        set tcp-mss {result.tcp_mss}")
        configs.append(f"    next")
        configs.append(f"end")

    elif platform == Platform.LINUX:
        configs.append(f"# Tunnel MTU and MSS configuration")
        configs.append(f"# Physical MTU: {result.physical_mtu}, Overhead: {result.total_overhead} bytes")
        configs.append(f"ip link set dev {interface} mtu {result.tunnel_mtu}")
        configs.append(f"iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN \\")
        configs.append(f"    -o {interface} -j TCPMSS --set-mss {result.tcp_mss}")
        configs.append(f"# Or clamp to PMTU:")
        configs.append(f"# iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu")

    elif platform == Platform.CISCO_NXOS:
        configs.append(f"! Tunnel MTU and MSS configuration for {interface}")
        configs.append(f"! Physical MTU: {result.physical_mtu}, Overhead: {result.total_overhead} bytes")
        configs.append(f"interface {interface}")
        configs.append(f"  mtu {result.tunnel_mtu}")
        configs.append(f"  ip tcp adjust-mss {result.tcp_mss}")

    elif platform == Platform.NOKIA_SRLINUX:
        configs.append(f"# Nokia SR Linux - Tunnel MTU configuration")
        configs.append(f"# Physical MTU: {result.physical_mtu}, Overhead: {result.total_overhead} bytes")
        configs.append(f"set / interface {interface} mtu {result.tunnel_mtu}")
        configs.append(f"# Note: TCP MSS clamping typically done via ACL-based filters or routing policy")
        configs.append(f"# Recommended TCP MSS: {result.tcp_mss}")

    elif platform == Platform.NOKIA_SROS:
        configs.append(f"# Nokia SR OS (7750/7950) - Tunnel MTU configuration")
        configs.append(f"# Physical MTU: {result.physical_mtu}, Overhead: {result.total_overhead} bytes")
        configs.append(f"configure router interface \"{interface}\" ip-mtu {result.tunnel_mtu}")
        configs.append(f"configure router policy-options")
        configs.append(f"    policy-statement \"tcp-mss-clamp\"")
        configs.append(f"        entry 10")
        configs.append(f"            action accept tcp-mss-adjust {result.tcp_mss}")

    elif platform == Platform.ARISTA_EOS:
        configs.append(f"! Arista EOS - Tunnel MTU and MSS configuration for {interface}")
        configs.append(f"! Physical MTU: {result.physical_mtu}, Overhead: {result.total_overhead} bytes")
        configs.append(f"interface {interface}")
        configs.append(f"   mtu {result.tunnel_mtu}")
        configs.append(f"   ip tcp mss ceiling {result.tcp_mss} both")

    elif platform == Platform.MIKROTIK:
        configs.append(f"# MikroTik RouterOS - Tunnel MTU and MSS configuration")
        configs.append(f"# Physical MTU: {result.physical_mtu}, Overhead: {result.total_overhead} bytes")
        configs.append(f"/interface set {interface} mtu={result.tunnel_mtu}")
        configs.append(f"/ip firewall mangle add chain=forward protocol=tcp tcp-flags=syn \\")
        configs.append(f"    out-interface={interface} action=change-mss new-mss={result.tcp_mss}")

    elif platform == Platform.HUAWEI_VRP:
        configs.append(f"# Huawei VRP - Tunnel MTU and MSS configuration")
        configs.append(f"# Physical MTU: {result.physical_mtu}, Overhead: {result.total_overhead} bytes")
        configs.append(f"interface {interface}")
        configs.append(f" mtu {result.tunnel_mtu}")
        configs.append(f" tcp adjust-mss {result.tcp_mss}")

    elif platform == Platform.VYOS:
        configs.append(f"# VyOS - Tunnel MTU and MSS configuration")
        configs.append(f"# Physical MTU: {result.physical_mtu}, Overhead: {result.total_overhead} bytes")
        configs.append(f"set interfaces tunnel {interface} mtu {result.tunnel_mtu}")
        configs.append(f"set firewall options interface {interface} adjust-mss {result.tcp_mss}")

    else:
        configs.append(f"# Unsupported platform: {platform.value}")
        configs.append(f"# Physical MTU: {result.physical_mtu}, Overhead: {result.total_overhead} bytes")
        configs.append(f"# Recommended Tunnel MTU: {result.tunnel_mtu}")
        configs.append(f"# Recommended TCP MSS: {result.tcp_mss}")

    return "\n".join(configs)


def get_common_scenarios() -> dict:
    """
    Return pre-calculated values for common tunnel scenarios.
    Useful for quick reference without specifying all parameters.
    """
    scenarios = {}

    # DMVPN Phase 3 with AES-256-GCM (common enterprise setup)
    result = calculate_mtu(
        TunnelType.GRE_IPSEC,
        encryption=EncryptionAlgorithm.AES_256_GCM,
        auth=AuthAlgorithm.GCM,
    )
    scenarios["dmvpn_aes256gcm"] = {
        "name": "DMVPN Phase 3 (AES-256-GCM)",
        "tunnel_mtu": result.tunnel_mtu,
        "tcp_mss": result.tcp_mss,
        "overhead": result.total_overhead,
    }

    # DMVPN with NAT-T
    result = calculate_mtu(
        TunnelType.GRE_IPSEC,
        encryption=EncryptionAlgorithm.AES_256_GCM,
        auth=AuthAlgorithm.GCM,
        nat_traversal=True,
    )
    scenarios["dmvpn_nat_t"] = {
        "name": "DMVPN with NAT-T (AES-256-GCM)",
        "tunnel_mtu": result.tunnel_mtu,
        "tcp_mss": result.tcp_mss,
        "overhead": result.total_overhead,
    }

    # Site-to-site IPsec (tunnel mode)
    result = calculate_mtu(
        TunnelType.IPSEC_TUNNEL,
        encryption=EncryptionAlgorithm.AES_256_CBC,
        auth=AuthAlgorithm.SHA256,
    )
    scenarios["ipsec_s2s"] = {
        "name": "Site-to-Site IPsec (AES-256-CBC, SHA256)",
        "tunnel_mtu": result.tunnel_mtu,
        "tcp_mss": result.tcp_mss,
        "overhead": result.total_overhead,
    }

    # Pure GRE (no encryption)
    result = calculate_mtu(TunnelType.GRE)
    scenarios["gre_only"] = {
        "name": "GRE (no encryption)",
        "tunnel_mtu": result.tunnel_mtu,
        "tcp_mss": result.tcp_mss,
        "overhead": result.total_overhead,
    }

    # VXLAN
    result = calculate_mtu(TunnelType.VXLAN)
    scenarios["vxlan"] = {
        "name": "VXLAN",
        "tunnel_mtu": result.tunnel_mtu,
        "tcp_mss": result.tcp_mss,
        "overhead": result.total_overhead,
    }

    # WireGuard
    result = calculate_mtu(TunnelType.WIREGUARD)
    scenarios["wireguard"] = {
        "name": "WireGuard",
        "tunnel_mtu": result.tunnel_mtu,
        "tcp_mss": result.tcp_mss,
        "overhead": result.total_overhead,
    }

    return scenarios


# CLI interface for testing
if __name__ == "__main__":
    print("=" * 60)
    print("Tunnel MTU & MSS Calculator")
    print("=" * 60)

    print("\n### Common Scenarios (1500 byte physical MTU) ###\n")
    for key, scenario in get_common_scenarios().items():
        print(f"{scenario['name']}:")
        print(f"  Tunnel MTU: {scenario['tunnel_mtu']}")
        print(f"  TCP MSS:    {scenario['tcp_mss']}")
        print(f"  Overhead:   {scenario['overhead']} bytes")
        print()

    print("\n### Detailed DMVPN Calculation ###\n")
    result = calculate_mtu(
        TunnelType.GRE_IPSEC,
        encryption=EncryptionAlgorithm.AES_256_GCM,
        auth=AuthAlgorithm.GCM,
    )
    print(f"Physical MTU: {result.physical_mtu}")
    print(f"Tunnel MTU:   {result.tunnel_mtu}")
    print(f"TCP MSS:      {result.tcp_mss}")
    print(f"\nOverhead breakdown:")
    for component, size in result.breakdown.to_dict().items():
        print(f"  {component}: {size} bytes")

    print("\n### Cisco IOS Configuration ###\n")
    print(generate_config(result, Platform.CISCO_IOS, "Tunnel100"))

    print("\n### Juniper JunOS Configuration ###\n")
    print(generate_config(result, Platform.JUNIPER_JUNOS, "st0.0"))
