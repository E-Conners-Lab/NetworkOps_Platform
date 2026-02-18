#!/usr/bin/env python3
"""
Generate network device configs from NetBox data using Jinja2 templates.

Supports FRR (containerlab) and IOS-XE (Cisco C8000V) device types.

Usage:
    python scripts/generate_configs.py --device R10                      # FRR, print to stdout
    python scripts/generate_configs.py --all --diff                      # FRR (default), diff all
    python scripts/generate_configs.py --type iosxe --device R6 --diff   # IOS-XE, diff one device
    python scripts/generate_configs.py --type iosxe --all --write        # IOS-XE, write all
    python scripts/generate_configs.py --type all --all --diff           # Both types, diff all
"""

import argparse
import difflib
import ipaddress
import os
import sys

import jinja2

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dotenv import load_dotenv

load_dotenv()

# Project root and paths
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FRR_TEMPLATE_DIR = os.path.join(PROJECT_ROOT, "templates", "frr")
FRR_CONFIG_DIR = os.path.join(PROJECT_ROOT, "containerlab", "configs")
IOSXE_TEMPLATE_DIR = os.path.join(PROJECT_ROOT, "templates", "iosxe")
IOSXE_CONFIG_DIR = os.path.join(PROJECT_ROOT, "configs", "iosxe")

# Device type slugs
FRR_DEVICE_TYPE = "frr"
IOSXE_DEVICE_TYPE = "c8000v"


def get_netbox_api():
    """Get authenticated pynetbox API client."""
    import pynetbox
    from config.vault_client import get_netbox_token

    url = os.getenv("NETBOX_URL", "http://localhost:8000")
    token = get_netbox_token()
    if not token:
        print("Error: NETBOX_API_TOKEN not set", file=sys.stderr)
        sys.exit(1)
    api = pynetbox.api(url, token=token)
    api.http_session.verify = False
    return api


# =============================================================================
# FRR functions (unchanged)
# =============================================================================


def collect_device_data(api, device_name: str) -> dict:
    """Fetch FRR device data from NetBox and build template context.

    Args:
        api: pynetbox API client
        device_name: Device name in NetBox (e.g. "edge1", "R9")

    Returns:
        Dict with all template variables for FRR config generation.
    """
    device = api.dcim.devices.get(name=device_name)
    if not device:
        raise ValueError(f"Device not found in NetBox: {device_name}")

    if device.device_type and device.device_type.slug != FRR_DEVICE_TYPE:
        raise ValueError(
            f"{device_name} is not an FRR device (type: {device.device_type.slug})"
        )

    cf = device.custom_fields or {}

    FRR_INTF_PREFIXES = ("eth", "lo", "gre", "tun", "vti", "bond", "br", "dummy")
    nb_interfaces = list(api.dcim.interfaces.filter(device_id=device.id))
    interfaces = []
    lo_interface = None

    for intf in nb_interfaces:
        if intf.name == "eth0":
            continue
        if not any(intf.name.startswith(p) for p in FRR_INTF_PREFIXES):
            continue

        ips = list(api.ipam.ip_addresses.filter(interface_id=intf.id))
        ip_address = str(ips[0].address) if ips else None

        intf_data = {
            "name": intf.name,
            "description": intf.description or None,
            "ip_address": ip_address,
            "ospf": None,
        }

        if intf.name == "lo":
            lo_interface = intf_data
        else:
            interfaces.append(intf_data)

    interfaces.sort(key=lambda x: x["name"])
    if lo_interface:
        interfaces.append(lo_interface)

    router_id = None
    if lo_interface and lo_interface["ip_address"]:
        router_id = lo_interface["ip_address"].split("/")[0]

    ospf_interfaces_raw = cf.get("ospf_interfaces") or []
    ospf_networks = []

    for oi in ospf_interfaces_raw:
        if "network" in oi:
            ospf_networks.append(oi)
        elif "name" in oi:
            ospf_settings = {}
            if "area" in oi and oi["area"] is not None:
                ospf_settings["area"] = oi["area"]
            if oi.get("mtu_ignore"):
                ospf_settings["mtu_ignore"] = True
            if oi.get("network_type"):
                ospf_settings["network_type"] = oi["network_type"]
            if "priority" in oi and oi["priority"] is not None:
                ospf_settings["priority"] = oi["priority"]
            if oi.get("passive"):
                ospf_settings["passive"] = True

            for iface in interfaces:
                if iface["name"] == oi["name"]:
                    iface["ospf"] = ospf_settings if ospf_settings else None
                    break

    return {
        "hostname": device_name,
        "router_id": router_id,
        "static_routes": cf.get("static_routes") or [],
        "interfaces": interfaces,
        "bgp_asn": cf.get("bgp_asn"),
        "bgp_peers": cf.get("bgp_peers") or [],
        "bgp_networks": cf.get("bgp_networks") or [],
        "ospf_enabled": cf.get("ospf_enabled", False),
        "ospf_networks": ospf_networks,
        "ospf_redistribute": cf.get("ospf_redistribute") or [],
        "frr_extra_config": cf.get("frr_extra_config") or "",
    }


def get_jinja_env() -> jinja2.Environment:
    """Create Jinja2 environment for FRR templates."""
    return jinja2.Environment(
        loader=jinja2.FileSystemLoader(FRR_TEMPLATE_DIR),
        trim_blocks=True,
        lstrip_blocks=True,
        keep_trailing_newline=False,
    )


def render_frr_conf(env: jinja2.Environment, context: dict) -> str:
    """Render frr.conf from template and context."""
    template = env.get_template("frr.conf.j2")
    return template.render(**context)


def render_daemons(env: jinja2.Environment, context: dict) -> str:
    """Render daemons file from template and context."""
    template = env.get_template("daemons.j2")
    return template.render(**context)


def get_frr_devices(api) -> list[str]:
    """Get names of all FRR devices from NetBox."""
    devices = api.dcim.devices.filter(device_type=FRR_DEVICE_TYPE)
    return [d.name for d in devices]


# =============================================================================
# IOS-XE functions
# =============================================================================


def _intf_sort_key(name: str) -> tuple:
    """Sort interfaces: Loopback, Tunnel, GigabitEthernet — each by number."""
    import re

    type_order = {"Loopback": 0, "Tunnel": 1, "GigabitEthernet": 2}
    for prefix, order in type_order.items():
        if name.startswith(prefix):
            num_str = name[len(prefix):]
            try:
                num = int(num_str)
            except ValueError:
                num = 0
            return (order, num)
    return (99, 0)


def collect_iosxe_device_data(api, device_name: str) -> dict:
    """Fetch IOS-XE device data from NetBox and build template context.

    Args:
        api: pynetbox API client
        device_name: Device name (e.g. "R1", "R6")

    Returns:
        Dict with all template variables for IOS-XE config generation.
    """
    device = api.dcim.devices.get(name=device_name)
    if not device:
        raise ValueError(f"Device not found in NetBox: {device_name}")

    if device.device_type and device.device_type.slug != IOSXE_DEVICE_TYPE:
        raise ValueError(
            f"{device_name} is not an IOS-XE device (type: {device.device_type.slug})"
        )

    if device.role and device.role.slug != "router":
        raise ValueError(
            f"{device_name} is not a router (role: {device.role.slug})"
        )

    cf = device.custom_fields or {}

    # Get interface extra lines map
    intf_extra = cf.get("iosxe_interface_extra") or {}

    # Get all interfaces from NetBox
    nb_interfaces = list(api.dcim.interfaces.filter(device_id=device.id))
    interfaces = []

    for intf in nb_interfaces:
        # Get IP addresses
        ips = list(api.ipam.ip_addresses.filter(interface_id=intf.id))

        ip_address = None
        netmask = None
        if ips:
            addr_str = str(ips[0].address)  # e.g. "10.0.12.1/30"
            network = ipaddress.IPv4Interface(addr_str)
            ip_address = str(network.ip)
            netmask = str(network.netmask)

        # Look up per-interface OSPF from ospf_interfaces custom field
        ospf_process_id = None
        ospf_area = None
        ospf_network_type = None

        ospf_interfaces_raw = cf.get("ospf_interfaces") or []
        for oi in ospf_interfaces_raw:
            if oi.get("name") == intf.name:
                ospf_process_id = oi.get("process_id")
                ospf_area = oi.get("area")
                ospf_network_type = oi.get("network_type")
                break

        # Extract special lines and split ip vs non-ip extras
        raw_extra = list(intf_extra.get(intf.name, []))
        dhcp_client_id = None
        vrf = None
        ip_extra_lines = []   # ip * lines → before OSPF
        extra_lines = []      # non-ip lines → after negotiation auto
        for line in raw_extra:
            if line.startswith("ip dhcp client client-id "):
                dhcp_client_id = line.split()[-1]
            elif line.startswith("vrf forwarding "):
                vrf = line.split()[-1]
            elif line.startswith("ip ") or line.startswith("no ip "):
                ip_extra_lines.append(line)
            else:
                extra_lines.append(line)

        intf_data = {
            "name": intf.name,
            "description": intf.description or None,
            "ip_address": ip_address,
            "netmask": netmask,
            "no_ip_address": ip_address is None,
            "shutdown": not intf.enabled,
            "negotiation_auto": intf.name.startswith("GigabitEthernet"),
            "dhcp": False,
            "dhcp_client_id": dhcp_client_id,
            "vrf": vrf,
            "ospf_process_id": ospf_process_id,
            "ospf_area": ospf_area,
            "ospf_network_type": ospf_network_type,
            "ip_extra_lines": ip_extra_lines,
            "extra_lines": extra_lines,
        }

        interfaces.append(intf_data)

    # Sort: Loopback → Tunnel → GigabitEthernet
    interfaces.sort(key=lambda x: _intf_sort_key(x["name"]))

    # Derive router-id from Loopback0 IP
    router_id = None
    for intf in interfaces:
        if intf["name"] == "Loopback0" and intf["ip_address"]:
            router_id = intf["ip_address"]
            break

    # Build OSPF network statements (entries with 'network' key)
    ospf_networks = []
    for oi in ospf_interfaces_raw:
        if "network" in oi:
            ospf_networks.append({
                "network": oi["network"],
                "wildcard": oi.get("wildcard", "0.0.0.0"),
                "area": oi["area"],
            })

    return {
        "interfaces": interfaces,
        "router_id": router_id,
        "iosxe_preamble": cf.get("iosxe_preamble") or "",
        "iosxe_postamble": cf.get("iosxe_postamble") or "",
        "iosxe_routing_extra": cf.get("iosxe_routing_extra") or "",
        "ospf_enabled": cf.get("ospf_enabled", False),
        "ospf_process_id": cf.get("ospf_process_id"),
        "ospf_passive_interfaces": cf.get("ospf_passive_interfaces") or [],
        "ospf_networks": ospf_networks,
        "ospf_redistribute": cf.get("ospf_redistribute") or [],
        "ospf_bfd": cf.get("ospf_bfd", False),
        "ospf_areas": cf.get("ospf_areas") or {},
        "bgp_asn": cf.get("bgp_asn"),
        "bgp_peers": cf.get("bgp_peers") or [],
        "bgp_peer_groups": cf.get("bgp_peer_groups") or [],
        "bgp_address_families": cf.get("bgp_address_families") or [],
        "bgp_no_default_ipv4": cf.get("bgp_no_default_ipv4", False),
        "static_routes": cf.get("static_routes") or [],
        "ntp_config": cf.get("ntp_config"),
    }


def get_iosxe_jinja_env() -> jinja2.Environment:
    """Create Jinja2 environment for IOS-XE templates."""
    env = jinja2.Environment(
        loader=jinja2.FileSystemLoader(IOSXE_TEMPLATE_DIR),
        trim_blocks=True,
        lstrip_blocks=True,
        keep_trailing_newline=False,
    )
    return env


def render_iosxe_config(env: jinja2.Environment, context: dict) -> str:
    """Render IOS-XE running-config from template and context."""
    template = env.get_template("running-config.j2")
    return template.render(**context)


def get_iosxe_devices(api) -> list[str]:
    """Get names of all IOS-XE router devices from NetBox."""
    devices = api.dcim.devices.filter(device_type=IOSXE_DEVICE_TYPE, role="router")
    return [d.name for d in devices]


# =============================================================================
# Common functions
# =============================================================================


def show_diff(device_name: str, file_type: str, existing_path: str, generated: str) -> bool:
    """Show unified diff between existing and generated config.

    Returns True if files differ, False if identical.
    """
    if not os.path.exists(existing_path):
        print(f"  {file_type}: {existing_path} does not exist (new file)")
        return True

    with open(existing_path) as f:
        existing = f.read()

    if existing == generated:
        print(f"  {file_type}: identical")
        return False

    diff = difflib.unified_diff(
        existing.splitlines(keepends=True),
        generated.splitlines(keepends=True),
        fromfile=f"{existing_path} (current)",
        tofile=f"{existing_path} (generated)",
    )
    diff_text = "".join(diff)
    print(f"  {file_type}:")
    print(diff_text)
    return True


def main():
    parser = argparse.ArgumentParser(description="Generate network configs from NetBox")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--device", help="Generate config for a specific device")
    group.add_argument("--all", action="store_true", help="Generate configs for all devices")
    parser.add_argument("--type", choices=["frr", "iosxe", "all"], default="frr",
                        help="Device type to generate (default: frr)")
    parser.add_argument("--diff", action="store_true", help="Show diff against existing config files")
    parser.add_argument("--write", action="store_true", help="Write generated configs to files")
    parser.add_argument("--output-dir", help="Override output directory")
    args = parser.parse_args()

    api = get_netbox_api()

    types_to_run = []
    if args.type == "all":
        types_to_run = ["frr", "iosxe"]
    else:
        types_to_run = [args.type]

    any_diff = False

    for config_type in types_to_run:
        if config_type == "frr":
            any_diff = any_diff or _run_frr(api, args)
        elif config_type == "iosxe":
            any_diff = any_diff or _run_iosxe(api, args)

    if args.diff:
        if any_diff:
            print("\nDifferences found. Use --write to apply generated configs.")
            sys.exit(1)
        else:
            print("\nAll configs match.")


def _run_frr(api, args) -> bool:
    """Run FRR config generation. Returns True if any diffs found."""
    env = get_jinja_env()
    output_dir = args.output_dir or FRR_CONFIG_DIR

    if args.all:
        device_names = get_frr_devices(api)
        if not device_names:
            print("No FRR devices found in NetBox")
            return False
        print(f"Found {len(device_names)} FRR devices: {', '.join(device_names)}")
    else:
        device_names = [args.device]

    any_diff = False

    for name in device_names:
        print(f"\n=== {name} (FRR) ===")

        try:
            context = collect_device_data(api, name)
        except ValueError as e:
            print(f"  Error: {e}", file=sys.stderr)
            continue

        frr_conf = render_frr_conf(env, context)
        daemons = render_daemons(env, context)

        frr_conf_path = os.path.join(output_dir, f"{name}-frr.conf")
        daemons_path = os.path.join(output_dir, f"{name}-daemons")

        if args.diff:
            d1 = show_diff(name, "frr.conf", frr_conf_path, frr_conf)
            d2 = show_diff(name, "daemons", daemons_path, daemons)
            if d1 or d2:
                any_diff = True
        elif args.write:
            with open(frr_conf_path, "w") as f:
                f.write(frr_conf)
            print(f"  Wrote {frr_conf_path}")
            with open(daemons_path, "w") as f:
                f.write(daemons)
            print(f"  Wrote {daemons_path}")
        else:
            print(f"--- {name}-frr.conf ---")
            print(frr_conf)
            print(f"--- {name}-daemons ---")
            print(daemons)

    return any_diff


def _run_iosxe(api, args) -> bool:
    """Run IOS-XE config generation. Returns True if any diffs found."""
    env = get_iosxe_jinja_env()
    output_dir = args.output_dir or IOSXE_CONFIG_DIR

    if args.all:
        device_names = get_iosxe_devices(api)
        if not device_names:
            print("No IOS-XE routers found in NetBox")
            return False
        print(f"Found {len(device_names)} IOS-XE routers: {', '.join(device_names)}")
    else:
        device_names = [args.device]

    any_diff = False

    for name in device_names:
        print(f"\n=== {name} (IOS-XE) ===")

        try:
            context = collect_iosxe_device_data(api, name)
        except ValueError as e:
            print(f"  Error: {e}", file=sys.stderr)
            continue

        config = render_iosxe_config(env, context)

        config_path = os.path.join(output_dir, f"{name}.cfg")

        if args.diff:
            d = show_diff(name, "running-config", config_path, config)
            if d:
                any_diff = True
        elif args.write:
            os.makedirs(output_dir, exist_ok=True)
            with open(config_path, "w") as f:
                f.write(config)
            print(f"  Wrote {config_path}")
        else:
            print(f"--- {name}.cfg ---")
            print(config)

    return any_diff


if __name__ == "__main__":
    main()
