#!/usr/bin/env python3
"""
Collect IOS-XE running configs via SSH and push structured fields to NetBox.

Parses 'show running-config' into structured routing fields + verbatim blobs,
then updates NetBox custom fields. Does NOT modify NetBox interfaces or IPs.

Usage:
    python scripts/collect_iosxe_configs.py --device R6 --dry-run
    python scripts/collect_iosxe_configs.py --all
    python scripts/collect_iosxe_configs.py --device R1 --save-raw
"""

import argparse
import asyncio
import ipaddress
import logging
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dotenv import load_dotenv

load_dotenv()

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RAW_DIR = os.path.join(PROJECT_ROOT, "configs", "iosxe")

logger = logging.getLogger(__name__)

# States for the config parser state machine
PREAMBLE = "PREAMBLE"
INTERFACES = "INTERFACES"
ROUTING = "ROUTING"
POSTROUTE = "POSTROUTE"


def _cidr_to_dotted(prefix_len: int) -> str:
    """Convert CIDR prefix length to dotted-decimal netmask."""
    return str(ipaddress.IPv4Network(f"0.0.0.0/{prefix_len}", strict=False).netmask)


def _mask_to_wildcard(mask: str) -> str:
    """Convert dotted-decimal mask to wildcard mask."""
    octets = mask.split(".")
    return ".".join(str(255 - int(o)) for o in octets)


def parse_running_config(raw: str) -> dict:
    """Parse an IOS-XE running-config into structured fields + verbatim blobs.

    Returns a dict with keys matching NetBox custom field names:
        ospf_process_id, ospf_interfaces, ospf_passive_interfaces,
        ospf_redistribute, bgp_asn, bgp_peers, bgp_peer_groups,
        bgp_address_families, bgp_no_default_ipv4, static_routes,
        ntp_config, iosxe_preamble, iosxe_postamble, iosxe_routing_extra,
        iosxe_interface_extra, interfaces_parsed (for verification only),
        ospf_bfd, ospf_areas
    """
    lines = raw.splitlines()

    # Result containers
    preamble_lines = []
    postamble_lines = []
    routing_extra_lines = []

    interfaces_parsed = []  # [{name, ip_address, netmask, description, shutdown, ...}]
    interface_extra = {}  # {intf_name: [extra_lines]}

    ospf_process_id = None
    ospf_networks = []  # [{network, wildcard, area}]
    ospf_passive_interfaces = []
    ospf_redistribute = []
    ospf_bfd = False
    ospf_areas = {}  # {area_id: "stub" | "stub no-summary" | ...}

    bgp_asn = None
    bgp_peers = []
    bgp_peer_groups = []
    bgp_address_families = []
    bgp_no_default_ipv4 = False

    static_routes = []
    ntp_config = {"servers": [], "authenticate": False}

    # Per-interface OSPF data  {intf_name: {process_id, area, network_type}}
    intf_ospf = {}

    state = PREAMBLE
    current_intf = None
    current_intf_lines = []  # for extra lines
    current_block = None  # for multi-line routing blocks
    current_block_lines = []

    # Skip header lines (Building config, Current config, ! Last config, ! NVRAM)
    i = 0
    while i < len(lines):
        line = lines[i]
        stripped_line = line.strip()
        if line.startswith("Building configuration") or line.startswith("Current configuration"):
            i += 1
            continue
        if stripped_line.startswith("! Last configuration") or stripped_line.startswith("! NVRAM"):
            i += 1
            continue
        if stripped_line in ("", "!") and state == PREAMBLE and not preamble_lines:
            i += 1
            continue
        break

    while i < len(lines):
        line = lines[i]
        stripped = line.strip()

        if stripped == "end":
            i += 1
            continue

        if state == PREAMBLE:
            if line.startswith("interface "):
                state = INTERFACES
                continue  # re-process this line in INTERFACES state
            preamble_lines.append(line)
            i += 1

        elif state == INTERFACES:
            if line.startswith("interface "):
                # Save previous interface
                if current_intf is not None:
                    if current_intf_lines:
                        interface_extra[current_intf["name"]] = current_intf_lines
                    interfaces_parsed.append(current_intf)

                intf_name = line.split("interface ", 1)[1].strip()
                current_intf = {
                    "name": intf_name,
                    "ip_address": None,
                    "netmask": None,
                    "description": None,
                    "shutdown": False,
                    "negotiation_auto": False,
                    "no_ip_address": False,
                    "dhcp": False,
                    "dhcp_client_id": None,
                    "vrf": None,
                }
                current_intf_lines = []
                i += 1

            elif current_intf is not None and (line.startswith(" ") or line.startswith("!")):
                if stripped == "!" or stripped == "":
                    i += 1
                    continue

                # Parse known interface sub-commands
                if stripped.startswith("ip address "):
                    parts = stripped.split()
                    if "dhcp" in parts:
                        current_intf["dhcp"] = True
                    elif len(parts) >= 4:
                        current_intf["ip_address"] = parts[2]
                        current_intf["netmask"] = parts[3]
                elif stripped == "no ip address":
                    current_intf["no_ip_address"] = True
                elif stripped.startswith("description "):
                    current_intf["description"] = stripped[len("description "):]
                elif stripped == "shutdown":
                    current_intf["shutdown"] = True
                elif stripped == "negotiation auto":
                    current_intf["negotiation_auto"] = True
                elif stripped.startswith("vrf forwarding "):
                    current_intf["vrf"] = stripped.split()[-1]
                    current_intf_lines.append(stripped)
                elif stripped.startswith("ip dhcp client "):
                    current_intf_lines.append(stripped)
                elif stripped.startswith("ip ospf network "):
                    ntype = stripped.split("ip ospf network ", 1)[1]
                    intf_ospf.setdefault(current_intf["name"], {})["network_type"] = ntype
                elif re.match(r"ip ospf (\d+) area (\S+)", stripped):
                    m = re.match(r"ip ospf (\d+) area (\S+)", stripped)
                    intf_ospf.setdefault(current_intf["name"], {})["process_id"] = int(m.group(1))
                    intf_ospf.setdefault(current_intf["name"], {})["area"] = m.group(2)
                else:
                    # Everything else is extra
                    current_intf_lines.append(stripped)
                i += 1

            else:
                # Non-indented line and not an interface = end of interfaces section
                if current_intf is not None:
                    if current_intf_lines:
                        interface_extra[current_intf["name"]] = current_intf_lines
                    interfaces_parsed.append(current_intf)
                    current_intf = None
                    current_intf_lines = []
                state = ROUTING
                continue  # re-process in ROUTING state

        elif state == ROUTING:
            if stripped == "!" or stripped == "":
                # Flush any current block
                if current_block is not None:
                    if current_block == "ospf":
                        pass  # already parsed inline
                    elif current_block == "bgp":
                        pass  # already parsed inline
                    else:
                        # routing extra block
                        routing_extra_lines.extend(current_block_lines)
                    current_block = None
                    current_block_lines = []
                i += 1
                continue

            # Detect routing block starts
            if line.startswith("router ospf "):
                m = re.match(r"router ospf (\d+)", stripped)
                ospf_process_id = int(m.group(1))
                current_block = "ospf"
                current_block_lines = [line]
                i += 1
                # Parse OSPF block
                while i < len(lines):
                    ol = lines[i]
                    os_ = ol.strip()
                    if os_ == "!" or (not ol.startswith(" ") and os_ != ""):
                        break
                    if os_.startswith("router-id "):
                        pass  # We derive router-id from Loopback0
                    elif os_.startswith("passive-interface "):
                        ospf_passive_interfaces.append(os_.split("passive-interface ", 1)[1])
                    elif os_.startswith("network "):
                        # network X.X.X.X W.W.W.W area Y
                        parts = os_.split()
                        if len(parts) >= 5:
                            ospf_networks.append({
                                "network": parts[1],
                                "wildcard": parts[2],
                                "area": parts[4],
                            })
                    elif os_.startswith("redistribute "):
                        parts = os_.split()
                        entry = {"type": parts[1]}
                        if "route-map" in os_:
                            idx = parts.index("route-map")
                            entry["route_map"] = parts[idx + 1]
                        ospf_redistribute.append(entry)
                    elif os_ == "bfd all-interfaces":
                        ospf_bfd = True
                    elif os_.startswith("area "):
                        # area 4 stub / area 4 stub no-summary
                        parts = os_.split(maxsplit=2)
                        if len(parts) >= 3:
                            ospf_areas[parts[1]] = " ".join(parts[2:])
                    i += 1
                current_block = None
                current_block_lines = []
                continue

            elif line.startswith("router bgp "):
                m = re.match(r"router bgp (\d+)", stripped)
                bgp_asn = int(m.group(1))
                current_block = "bgp"
                i += 1
                in_af = False
                current_af = None
                # Parse BGP block
                while i < len(lines):
                    bl = lines[i]
                    bs = bl.strip()
                    if not bl.startswith(" ") and bs != "!" and bs != "":
                        break
                    if bs == "!" or bs == "":
                        i += 1
                        continue

                    if bs == "no bgp default ipv4-unicast":
                        bgp_no_default_ipv4 = True
                    elif bs.startswith("address-family "):
                        afi = bs.split("address-family ", 1)[1]
                        current_af = {"afi": afi, "neighbors": [], "networks": [], "rr_client_groups": []}
                        in_af = True
                    elif bs == "exit-address-family":
                        if current_af:
                            bgp_address_families.append(current_af)
                        current_af = None
                        in_af = False
                    elif in_af and current_af is not None:
                        if bs.startswith("neighbor "):
                            parts = bs.split()
                            peer_id = parts[1]
                            if "activate" in parts:
                                current_af["neighbors"].append({"peer": peer_id})
                            elif "route-reflector-client" in parts:
                                current_af["rr_client_groups"].append(peer_id)
                            elif "next-hop-self" in parts:
                                current_af.setdefault("next_hop_self_peers", []).append(peer_id)
                        elif bs.startswith("network "):
                            parts = bs.split()
                            net = {"prefix": parts[1]}
                            if "mask" in parts:
                                idx = parts.index("mask")
                                net["mask"] = parts[idx + 1]
                            current_af["networks"].append(net)
                    elif not in_af:
                        # Global BGP commands
                        if bs.startswith("neighbor ") and "peer-group" in bs:
                            parts = bs.split()
                            peer_id = parts[1]
                            if len(parts) == 3 and parts[2] == "peer-group":
                                # neighbor X peer-group (defines peer-group)
                                bgp_peer_groups.append({"name": peer_id})
                            else:
                                # neighbor X peer-group Y (assigns to peer-group)
                                pg_name = parts[parts.index("peer-group") + 1]
                                # Find existing peer and set peer_group
                                for p in bgp_peers:
                                    if p["neighbor"] == peer_id:
                                        p["peer_group"] = pg_name
                                        break
                                else:
                                    bgp_peers.append({"neighbor": peer_id, "peer_group": pg_name})
                        elif bs.startswith("neighbor ") and "remote-as" in bs:
                            parts = bs.split()
                            peer_id = parts[1]
                            remote_as = int(parts[parts.index("remote-as") + 1])
                            # Check if this is defining a peer-group's remote-as
                            for pg in bgp_peer_groups:
                                if pg["name"] == peer_id:
                                    pg["remote_as"] = remote_as
                                    break
                            else:
                                # Regular peer
                                existing = None
                                for p in bgp_peers:
                                    if p["neighbor"] == peer_id:
                                        existing = p
                                        break
                                if existing:
                                    existing["remote_as"] = remote_as
                                else:
                                    bgp_peers.append({"neighbor": peer_id, "remote_as": remote_as})
                        elif bs.startswith("neighbor ") and "update-source" in bs:
                            parts = bs.split()
                            peer_id = parts[1]
                            source = parts[parts.index("update-source") + 1]
                            # Try peer-groups first, then peers
                            for pg in bgp_peer_groups:
                                if pg["name"] == peer_id:
                                    pg["update_source"] = source
                                    break
                            else:
                                for p in bgp_peers:
                                    if p["neighbor"] == peer_id:
                                        p["update_source"] = source
                                        break
                        elif bs.startswith("neighbor ") and "description" in bs:
                            parts = bs.split()
                            peer_id = parts[1]
                            desc = bs.split("description ", 1)[1]
                            for p in bgp_peers:
                                if p["neighbor"] == peer_id:
                                    p["description"] = desc
                                    break
                        elif bs.startswith("neighbor ") and "ebgp-multihop" in bs:
                            parts = bs.split()
                            peer_id = parts[1]
                            hops = int(parts[parts.index("ebgp-multihop") + 1])
                            for p in bgp_peers:
                                if p["neighbor"] == peer_id:
                                    p["ebgp_multihop"] = hops
                                    break
                        elif bs.startswith("bgp router-id") or bs.startswith("bgp log-neighbor-changes"):
                            pass  # skip, derived from Loopback0 / implicit

                    i += 1
                current_block = None
                current_block_lines = []
                continue

            elif line.startswith("router "):
                # Non-OSPF/BGP routing block (eigrp, ospfv3, etc.)
                routing_extra_lines.append(line)
                i += 1
                while i < len(lines):
                    rl = lines[i]
                    rs = rl.strip()
                    if rs == "!":
                        routing_extra_lines.append(rl)
                        i += 1
                        # Check if next line continues (indented or starts with 'router')
                        if i < len(lines) and (lines[i].startswith(" ") or lines[i].startswith("router ")):
                            continue
                        break
                    if not rl.startswith(" ") and rs != "":
                        break
                    routing_extra_lines.append(rl)
                    i += 1
                continue

            else:
                # Non-router line in ROUTING state = transition to POSTROUTE
                state = POSTROUTE
                continue

        elif state == POSTROUTE:
            if stripped == "!" or stripped == "":
                postamble_lines.append(line)
                i += 1
                continue

            # Parse static routes
            if stripped.startswith("ip route "):
                parts = stripped.split()
                # ip route prefix mask next_hop [ad]
                if len(parts) >= 5:
                    route = {
                        "prefix": parts[2],
                        "mask": parts[3],
                        "next_hop": parts[4],
                    }
                    if len(parts) >= 6 and parts[5].isdigit():
                        route["ad"] = int(parts[5])
                    static_routes.append(route)
                else:
                    postamble_lines.append(line)
                i += 1
                continue

            # Parse NTP
            if stripped.startswith("ntp "):
                if stripped == "ntp authenticate":
                    ntp_config["authenticate"] = True
                elif stripped.startswith("ntp source "):
                    ntp_config["source"] = stripped.split()[-1]
                elif stripped.startswith("ntp master"):
                    parts = stripped.split()
                    ntp_config["master"] = int(parts[-1]) if len(parts) > 2 else 1
                elif stripped.startswith("ntp server "):
                    parts = stripped.split()
                    server_entry = {"address": parts[2]}
                    # Check for 'source Loopback0' etc.
                    if "source" in parts:
                        server_entry["source"] = parts[parts.index("source") + 1]
                    ntp_config["servers"].append(server_entry)
                else:
                    postamble_lines.append(line)
                i += 1
                continue

            # Everything else → postamble
            postamble_lines.append(line)
            i += 1

    # Build ospf_interfaces from per-interface OSPF data (for netbox custom field)
    ospf_interfaces = []
    for intf_name, ospf_data in intf_ospf.items():
        entry = {"name": intf_name}
        if "process_id" in ospf_data:
            entry["process_id"] = ospf_data["process_id"]
        if "area" in ospf_data:
            entry["area"] = ospf_data["area"]
        if "network_type" in ospf_data:
            entry["network_type"] = ospf_data["network_type"]
        ospf_interfaces.append(entry)

    # Add network statements to ospf_interfaces
    for net in ospf_networks:
        ospf_interfaces.append({
            "network": net["network"],
            "wildcard": net["wildcard"],
            "area": net["area"],
        })

    # Clean up preamble: remove trailing empty lines/bangs
    while preamble_lines and preamble_lines[-1].strip() in ("", "!"):
        preamble_lines.pop()

    # Clean up postamble: remove trailing empty lines/bangs
    while postamble_lines and postamble_lines[-1].strip() in ("", "!"):
        postamble_lines.pop()

    # Clean up routing extra: remove trailing empty lines/bangs
    while routing_extra_lines and routing_extra_lines[-1].strip() in ("", "!"):
        routing_extra_lines.pop()

    # Normalize NTP: don't store empty config
    has_ntp = ntp_config["authenticate"] or ntp_config["servers"] or ntp_config.get("source")
    if not has_ntp:
        ntp_config = None

    return {
        "ospf_enabled": ospf_process_id is not None,
        "ospf_process_id": ospf_process_id,
        "ospf_interfaces": ospf_interfaces,
        "ospf_passive_interfaces": ospf_passive_interfaces,
        "ospf_redistribute": ospf_redistribute,
        "ospf_bfd": ospf_bfd,
        "ospf_areas": ospf_areas,
        "bgp_asn": bgp_asn,
        "bgp_peers": bgp_peers,
        "bgp_peer_groups": bgp_peer_groups,
        "bgp_address_families": bgp_address_families,
        "bgp_no_default_ipv4": bgp_no_default_ipv4,
        "static_routes": static_routes,
        "ntp_config": ntp_config,
        "iosxe_preamble": "\n".join(preamble_lines),
        "iosxe_postamble": "\n".join(postamble_lines),
        "iosxe_routing_extra": "\n".join(routing_extra_lines) if routing_extra_lines else "",
        "iosxe_interface_extra": interface_extra,
        "interfaces_parsed": interfaces_parsed,
    }


async def collect_from_device(device_name: str, host: str) -> str:
    """SSH to device and retrieve running-config."""
    from core.scrapli_manager import get_ios_xe_connection

    async with get_ios_xe_connection(device_name) as conn:
        result = await conn.send_command("show running-config")
        return result.result


def push_to_netbox(api, device_name: str, parsed: dict) -> list[str]:
    """Update NetBox custom fields with parsed config data.

    Returns list of field names that were updated.
    """
    device = api.dcim.devices.get(name=device_name)
    if not device:
        raise ValueError(f"Device not found in NetBox: {device_name}")

    cf = device.custom_fields or {}
    updated = []

    # Map parsed fields to custom field names
    field_map = {
        "ospf_process_id": "ospf_process_id",
        "ospf_interfaces": "ospf_interfaces",
        "ospf_passive_interfaces": "ospf_passive_interfaces",
        "ospf_redistribute": "ospf_redistribute",
        "ospf_enabled": "ospf_enabled",
        "bgp_asn": "bgp_asn",
        "bgp_peers": "bgp_peers",
        "bgp_peer_groups": "bgp_peer_groups",
        "bgp_address_families": "bgp_address_families",
        "static_routes": "static_routes",
        "ntp_config": "ntp_config",
        "iosxe_preamble": "iosxe_preamble",
        "iosxe_postamble": "iosxe_postamble",
        "iosxe_routing_extra": "iosxe_routing_extra",
        "iosxe_interface_extra": "iosxe_interface_extra",
        "ospf_bfd": "ospf_bfd",
        "ospf_areas": "ospf_areas",
        "bgp_no_default_ipv4": "bgp_no_default_ipv4",
    }

    new_cf = {}
    for parsed_key, cf_key in field_map.items():
        new_val = parsed.get(parsed_key)
        # Normalize empty strings/lists/None for comparison
        old_val = cf.get(cf_key)
        if new_val != old_val:
            new_cf[cf_key] = new_val
            updated.append(cf_key)

    if new_cf:
        device.custom_fields = {**cf, **new_cf}
        device.save()

    return updated


def get_device_host(device_name: str) -> str:
    """Look up management IP for device."""
    from config.devices import DEVICES

    device = DEVICES.get(device_name)
    if device and "host" in device:
        return device["host"]
    raise ValueError(f"Device {device_name} not found in config.devices")


def get_iosxe_devices() -> list[str]:
    """Get list of IOS-XE router names from NetBox."""
    import pynetbox
    from config.vault_client import get_netbox_token

    url = os.getenv("NETBOX_URL", "http://localhost:8000")
    token = get_netbox_token()
    api = pynetbox.api(url, token=token)
    api.http_session.verify = False

    devices = api.dcim.devices.filter(device_type="c8000v", role="router")
    return [d.name for d in devices]


def main():
    parser = argparse.ArgumentParser(description="Collect IOS-XE configs and push to NetBox")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--device", help="Collect from a specific device")
    group.add_argument("--all", action="store_true", help="Collect from all IOS-XE routers")
    parser.add_argument("--dry-run", action="store_true", help="Parse and print, don't push to NetBox")
    parser.add_argument("--save-raw", action="store_true", help="Save raw show-run to configs/iosxe/")
    parser.add_argument("--from-file", help="Parse from a local file instead of SSH")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s: %(message)s",
    )

    if args.all:
        device_names = get_iosxe_devices()
        if not device_names:
            print("No IOS-XE routers found in NetBox")
            sys.exit(1)
        print(f"Found {len(device_names)} IOS-XE routers: {', '.join(device_names)}")
    else:
        device_names = [args.device]

    import pynetbox
    from config.vault_client import get_netbox_token

    url = os.getenv("NETBOX_URL", "http://localhost:8000")
    token = get_netbox_token()
    api = pynetbox.api(url, token=token)
    api.http_session.verify = False

    for name in device_names:
        print(f"\n=== {name} ===")

        try:
            if args.from_file:
                with open(args.from_file) as f:
                    raw = f.read()
            else:
                host = get_device_host(name)
                print(f"  Connecting to {host}...")
                raw = asyncio.run(collect_from_device(name, host))

            if args.save_raw:
                os.makedirs(RAW_DIR, exist_ok=True)
                raw_path = os.path.join(RAW_DIR, f"{name}_reference.cfg")
                with open(raw_path, "w") as f:
                    f.write(raw)
                print(f"  Saved raw config to {raw_path}")

            parsed = parse_running_config(raw)

            if args.dry_run:
                import json
                # Print structured fields
                display = {k: v for k, v in parsed.items() if k != "interfaces_parsed"}
                print(json.dumps(display, indent=2))

                # Print interface summary
                print(f"\n  Interfaces found: {len(parsed['interfaces_parsed'])}")
                for intf in parsed["interfaces_parsed"]:
                    ip = intf.get("ip_address") or ("dhcp" if intf.get("dhcp") else "no ip")
                    shut = " [shutdown]" if intf.get("shutdown") else ""
                    print(f"    {intf['name']}: {ip}{shut}")
            else:
                updated = push_to_netbox(api, name, parsed)
                if updated:
                    print(f"  Updated {len(updated)} fields: {', '.join(updated)}")
                else:
                    print("  No changes needed")

        except Exception as e:
            print(f"  Error: {e}", file=sys.stderr)
            logger.debug("Full traceback:", exc_info=True)
            if not args.all:
                sys.exit(1)


if __name__ == "__main__":
    main()
