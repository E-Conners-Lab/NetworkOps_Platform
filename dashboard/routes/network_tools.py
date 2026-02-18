"""
Network Tools API Routes.

MTU calculator and Subnet calculator endpoints.
"""

import logging

from flask import Blueprint, jsonify, request
from core.errors import safe_error_response, ValidationError
from dashboard.auth import jwt_required

logger = logging.getLogger(__name__)

network_tools_bp = Blueprint('network_tools', __name__)


# =============================================================================
# MTU & MSS Calculator
# =============================================================================

@network_tools_bp.route('/api/mtu/calculate', methods=['POST'])
@jwt_required
def calculate_mtu_endpoint():
    """
    Calculate optimal tunnel MTU and TCP MSS for VPN tunnels.

    Request body:
    {
        "tunnel_type": "gre_ipsec",  // Required: gre, gre_ipsec, ipsec_tunnel, ipsec_transport, vxlan, wireguard
        "physical_mtu": 1500,        // Optional, default 1500
        "encryption": "aes-256-gcm", // Optional for IPsec tunnels
        "auth": "sha256",            // Optional, auto-selected for GCM
        "nat_traversal": false,      // Optional, default false
        "platform": "cisco_ios",     // Optional: generates config commands
        "interface": "Tunnel100"     // Optional, default Tunnel0
    }

    Returns calculated MTU/MSS values, overhead breakdown, and optional config.
    """
    from core.mtu_calculator import (
        TunnelType, EncryptionAlgorithm, AuthAlgorithm, Platform,
        calculate_mtu, generate_config
    )

    data = request.get_json() or {}
    tunnel_type = data.get('tunnel_type')

    if not tunnel_type:
        return jsonify({'error': 'tunnel_type is required'}), 400

    # Map string inputs to enums
    tunnel_type_map = {
        'gre': TunnelType.GRE,
        'gre_ipsec': TunnelType.GRE_IPSEC,
        'ipsec_tunnel': TunnelType.IPSEC_TUNNEL,
        'ipsec_transport': TunnelType.IPSEC_TRANSPORT,
        'vxlan': TunnelType.VXLAN,
        'geneve': TunnelType.GENEVE,
        'wireguard': TunnelType.WIREGUARD,
    }

    encryption_map = {
        'aes-128-cbc': EncryptionAlgorithm.AES_128_CBC,
        'aes-256-cbc': EncryptionAlgorithm.AES_256_CBC,
        'aes-128-gcm': EncryptionAlgorithm.AES_128_GCM,
        'aes-256-gcm': EncryptionAlgorithm.AES_256_GCM,
        'des-cbc': EncryptionAlgorithm.DES_CBC,
        '3des-cbc': EncryptionAlgorithm.THREE_DES_CBC,
        'chacha20-poly1305': EncryptionAlgorithm.CHACHA20_POLY1305,
    }

    auth_map = {
        'sha1': AuthAlgorithm.SHA1,
        'sha256': AuthAlgorithm.SHA256,
        'sha384': AuthAlgorithm.SHA384,
        'sha512': AuthAlgorithm.SHA512,
        'md5': AuthAlgorithm.MD5,
        'gcm': AuthAlgorithm.GCM,
    }

    platform_map = {
        'cisco_ios': Platform.CISCO_IOS,
        'cisco_iosxe': Platform.CISCO_IOSXE,
        'cisco_asa': Platform.CISCO_ASA,
        'cisco_nxos': Platform.CISCO_NXOS,
        'juniper_junos': Platform.JUNIPER_JUNOS,
        'palo_alto': Platform.PALO_ALTO,
        'fortinet': Platform.FORTINET,
        'linux': Platform.LINUX,
        'nokia_srlinux': Platform.NOKIA_SRLINUX,
        'nokia_sros': Platform.NOKIA_SROS,
        'arista_eos': Platform.ARISTA_EOS,
        'mikrotik': Platform.MIKROTIK,
        'huawei_vrp': Platform.HUAWEI_VRP,
        'vyos': Platform.VYOS,
    }

    # Validate tunnel type
    if tunnel_type.lower() not in tunnel_type_map:
        return jsonify({
            'error': f'Unknown tunnel type: {tunnel_type}',
            'valid_types': list(tunnel_type_map.keys())
        }), 400

    # Convert inputs
    tt = tunnel_type_map[tunnel_type.lower()]
    encryption = data.get('encryption')
    auth = data.get('auth')
    enc = encryption_map.get(encryption.lower()) if encryption else None
    au = auth_map.get(auth.lower()) if auth else None

    platform = data.get('platform')
    plat = platform_map.get(platform.lower()) if platform else None

    try:
        result = calculate_mtu(
            tunnel_type=tt,
            physical_mtu=data.get('physical_mtu', 1500),
            encryption=enc,
            auth=au,
            nat_traversal=data.get('nat_traversal', False),
        )
    except ValueError as e:
        # User input validation errors - safe to expose
        raise ValidationError(str(e))
    except Exception as e:
        return safe_error_response(e, "calculate MTU")

    response = result.to_dict()

    # Add config if platform specified
    if plat:
        interface = data.get('interface', 'Tunnel0')
        response['config'] = generate_config(result, plat, interface)
        response['platform'] = platform

    return jsonify(response)


@network_tools_bp.route('/api/mtu/scenarios')
@jwt_required
def get_mtu_scenarios_endpoint():
    """
    Get pre-calculated MTU/MSS values for common tunnel scenarios.

    Returns recommended settings for:
    - DMVPN Phase 3 (AES-256-GCM)
    - DMVPN with NAT-T
    - Site-to-Site IPsec (AES-256-CBC)
    - Pure GRE (no encryption)
    - VXLAN
    - WireGuard
    """
    from core.mtu_calculator import get_common_scenarios

    scenarios = get_common_scenarios()

    return jsonify({
        'physical_mtu': 1500,
        'scenarios': scenarios,
        'note': 'Use POST /api/mtu/calculate for custom parameters'
    })


# =============================================================================
# Subnet Calculator Endpoints
# =============================================================================

@network_tools_bp.route('/api/subnet/calculate', methods=['POST'])
@jwt_required
def calculate_subnet_endpoint():
    """
    Calculate subnet information from an IP address.

    Request body:
    {
        "address": "192.168.1.0/24",    // Required: IP in CIDR or plain format
        "netmask": "255.255.255.0"      // Optional: if not using CIDR
    }
    """
    from core.subnet_calculator import calculate_subnet

    data = request.get_json()
    if not data or 'address' not in data:
        return jsonify({'error': 'Missing required field: address'}), 400

    try:
        result = calculate_subnet(
            address=data['address'],
            netmask=data.get('netmask')
        )
        return jsonify(result.to_dict())
    except ValueError as e:
        # User input validation - safe to expose
        raise ValidationError(str(e))


@network_tools_bp.route('/api/subnet/split', methods=['POST'])
@jwt_required
def split_subnet_endpoint():
    """
    Split a network into smaller subnets (VLSM).

    Request body:
    {
        "network": "192.168.1.0/24",    // Required: Network in CIDR notation
        "new_prefix": 26                 // Required: New prefix length
    }
    """
    from core.subnet_calculator import split_subnet

    data = request.get_json()
    if not data or 'network' not in data or 'new_prefix' not in data:
        return jsonify({'error': 'Missing required fields: network, new_prefix'}), 400

    try:
        subnets = split_subnet(
            network=data['network'],
            new_prefix=int(data['new_prefix'])
        )
        return jsonify({
            'original_network': data['network'],
            'new_prefix': data['new_prefix'],
            'subnet_count': len(subnets),
            'subnets': subnets
        })
    except ValueError as e:
        # User input validation - safe to expose
        raise ValidationError(str(e))


@network_tools_bp.route('/api/subnet/reference')
@jwt_required
def get_subnet_reference_endpoint():
    """Get a reference table of common subnet sizes."""
    from core.subnet_calculator import get_common_subnets

    return jsonify({
        'common_subnets': get_common_subnets(),
        'notes': {
            'hosts': 'Usable host addresses (excluding network and broadcast)',
            '/31': 'Point-to-point links (RFC 3021) - both addresses usable',
            '/32': 'Host routes - single address'
        }
    })


@network_tools_bp.route('/api/subnet/convert', methods=['POST'])
@jwt_required
def convert_netmask_endpoint():
    """
    Convert between CIDR prefix and dotted decimal netmask.

    Request body:
    {
        "value": "24"               // Prefix length or netmask
    }
    """
    from core.subnet_calculator import cidr_to_netmask, netmask_to_cidr

    data = request.get_json()
    if not data or 'value' not in data:
        return jsonify({'error': 'Missing required field: value'}), 400

    value = str(data['value'])

    try:
        if value.isdigit():
            prefix = int(value)
            netmask = cidr_to_netmask(prefix)
            return jsonify({
                'prefix_length': prefix,
                'netmask': netmask,
                'cidr': f'/{prefix}'
            })
        else:
            prefix = netmask_to_cidr(value)
            return jsonify({
                'netmask': value,
                'prefix_length': prefix,
                'cidr': f'/{prefix}'
            })
    except ValueError as e:
        # User input validation - safe to expose
        raise ValidationError(str(e))
