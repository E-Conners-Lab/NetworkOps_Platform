"""
Stateful in-memory device simulator for demo mode.

Provides realistic IOS-XE command output without requiring real network devices.
All state is held in memory and reset when the process restarts.
"""

import random
import re
from datetime import datetime


class DemoDeviceManager:
    """Stateful in-memory device simulator for demo mode."""

    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        if self._initialized:
            return
        self._initialized = True
        self._load_initial_state()

    def _load_initial_state(self):
        """Load initial device state from fixtures."""
        from core.demo.fixtures import (
            DEMO_DEVICES,
            DEMO_BGP_PEERS,
            DEMO_OSPF_ADJACENCIES,
            DEMO_TOPOLOGY_LINKS,
        )

        self._fixtures_devices = DEMO_DEVICES
        self._topology_links = DEMO_TOPOLOGY_LINKS
        self.devices: dict[str, dict] = {}

        for name, device in DEMO_DEVICES.items():
            self.devices[name] = {
                "info": device,
                "interfaces": self._generate_interfaces(name, device),
                "bgp_peers": DEMO_BGP_PEERS.get(name, []),
                "ospf_adjacencies": DEMO_OSPF_ADJACENCIES.get(name, []),
                "cpu": round(random.uniform(5, 30), 1),
                "memory_used": random.randint(400000, 800000),
                "memory_free": random.randint(1200000, 1600000),
                "uptime": f"{random.randint(1, 90)} days, {random.randint(0, 23)} hours, {random.randint(0, 59)} minutes",
                "version": device.get("platform", "Unknown"),
                "hostname": name,
            }

    # ------------------------------------------------------------------
    # Interface generation
    # ------------------------------------------------------------------

    _INTERFACE_TEMPLATES: dict[str, list[dict]] = {
        "R1": [
            {"name": "GigabitEthernet1", "ip": "10.1.0.1", "mask": "255.255.255.0", "desc": "LAN"},
            {"name": "GigabitEthernet2", "ip": "10.12.0.1", "mask": "255.255.255.252", "desc": "to R2"},
            {"name": "Loopback0", "ip": "198.51.100.1", "mask": "255.255.255.255", "desc": "Router-ID"},
        ],
        "R2": [
            {"name": "GigabitEthernet1", "ip": "10.2.0.1", "mask": "255.255.255.0", "desc": "LAN"},
            {"name": "GigabitEthernet2", "ip": "10.12.0.2", "mask": "255.255.255.252", "desc": "to R1"},
            {"name": "GigabitEthernet3", "ip": "10.23.0.1", "mask": "255.255.255.252", "desc": "to R3"},
            {"name": "Loopback0", "ip": "198.51.100.2", "mask": "255.255.255.255", "desc": "Router-ID"},
        ],
        "R3": [
            {"name": "GigabitEthernet1", "ip": "10.3.0.1", "mask": "255.255.255.0", "desc": "LAN"},
            {"name": "GigabitEthernet2", "ip": "10.23.0.2", "mask": "255.255.255.252", "desc": "to R2"},
            {"name": "GigabitEthernet3", "ip": "10.34.0.1", "mask": "255.255.255.252", "desc": "to R4"},
            {"name": "GigabitEthernet4", "ip": "10.35.0.1", "mask": "255.255.255.252", "desc": "to edge1"},
            {"name": "Loopback0", "ip": "198.51.100.3", "mask": "255.255.255.255", "desc": "Router-ID"},
        ],
        "R4": [
            {"name": "GigabitEthernet1", "ip": "10.4.0.1", "mask": "255.255.255.0", "desc": "LAN"},
            {"name": "GigabitEthernet2", "ip": "10.34.0.2", "mask": "255.255.255.252", "desc": "to R3"},
            {"name": "Loopback0", "ip": "198.51.100.4", "mask": "255.255.255.255", "desc": "Router-ID"},
        ],
        "Switch-R1": [
            {"name": "GigabitEthernet1/0/1", "ip": "unassigned", "mask": "", "desc": "to R1"},
            {"name": "Vlan1", "ip": "10.1.1.1", "mask": "255.255.255.0", "desc": "Management"},
            {"name": "Loopback0", "ip": "198.51.100.11", "mask": "255.255.255.255", "desc": "Router-ID"},
        ],
        "Switch-R2": [
            {"name": "GigabitEthernet1/0/1", "ip": "unassigned", "mask": "", "desc": "to R2"},
            {"name": "Vlan1", "ip": "10.2.1.1", "mask": "255.255.255.0", "desc": "Management"},
            {"name": "Loopback0", "ip": "198.51.100.22", "mask": "255.255.255.255", "desc": "Router-ID"},
        ],
        "Alpine-1": [
            {"name": "eth0", "ip": "10.3.0.10", "mask": "255.255.255.0", "desc": "LAN"},
        ],
        "edge1": [
            {"name": "eth1", "ip": "10.200.1.1", "mask": "255.255.255.252", "desc": "to spine1"},
            {"name": "eth2", "ip": "10.35.0.2", "mask": "255.255.255.252", "desc": "to R3"},
            {"name": "lo", "ip": "10.255.0.2", "mask": "255.255.255.255", "desc": "Loopback"},
        ],
    }

    def _generate_interfaces(self, name: str, device: dict) -> list[dict]:
        """Create interface list for a device."""
        templates = self._INTERFACE_TEMPLATES.get(name, [])
        interfaces = []
        for tmpl in templates:
            interfaces.append({
                "name": tmpl["name"],
                "ip_address": tmpl["ip"],
                "subnet_mask": tmpl["mask"],
                "description": tmpl["desc"],
                "status": "up",
                "protocol": "up",
                "bandwidth": 1000000 if "Loopback" not in tmpl["name"] and "lo" != tmpl["name"] else 8000000,
                "mtu": 1500,
                "in_packets": random.randint(100000, 9999999),
                "out_packets": random.randint(100000, 9999999),
                "in_errors": 0,
                "out_errors": 0,
                "crc_errors": 0,
            })
        return interfaces

    # ------------------------------------------------------------------
    # Command dispatch
    # ------------------------------------------------------------------

    def handle_command(self, device_name: str, command: str) -> str:
        """Return realistic CLI output for a show command.

        Args:
            device_name: Device to query.
            command: CLI command string.

        Returns:
            Simulated command output as a string.
        """
        state = self.devices.get(device_name)
        if state is None:
            return f"% Device '{device_name}' not found in demo inventory"

        cmd = command.strip().lower()

        if cmd.startswith("show version"):
            return self._show_version(device_name, state)
        if cmd in ("show ip interface brief", "show ip int brief", "sh ip int br"):
            return self._show_ip_interface_brief(device_name, state)
        if cmd.startswith("show ip ospf neighbor"):
            return self._show_ip_ospf_neighbor(device_name, state)
        if cmd.startswith("show ip bgp summary") or cmd.startswith("show bgp summary"):
            return self._show_ip_bgp_summary(device_name, state)
        if cmd.startswith("show ip route"):
            return self._show_ip_route(device_name, state)
        if cmd.startswith("show running-config") or cmd.startswith("show run"):
            return self._show_running_config(device_name, state)
        if cmd.startswith("show ip arp"):
            return self._show_ip_arp(device_name, state)
        if cmd.startswith("show interfaces") or cmd.startswith("show int"):
            return self._show_interfaces(device_name, state)
        if cmd.startswith("ping "):
            return self._ping(cmd, state)
        if cmd.startswith("show inventory"):
            return self._show_inventory(device_name, state)
        if cmd.startswith("show processes cpu") or cmd.startswith("show proc cpu"):
            return self._show_processes_cpu(device_name, state)

        # Unknown command — return empty
        return ""

    def handle_config(self, device_name: str, commands: list[str]) -> str:
        """Process configuration commands.

        Supports interface shutdown/no shutdown toggling. All other commands
        are accepted silently.

        Args:
            device_name: Target device.
            commands: List of config-mode commands.

        Returns:
            Status message.
        """
        state = self.devices.get(device_name)
        if state is None:
            return f"% Device '{device_name}' not found in demo inventory"

        current_intf = None
        for cmd in commands:
            cmd_stripped = cmd.strip().lower()

            # Track which interface context we are in
            intf_match = re.match(r"interface\s+(.+)", cmd_stripped)
            if intf_match:
                intf_name = intf_match.group(1)
                # Find matching interface (case-insensitive)
                for intf in state["interfaces"]:
                    if intf["name"].lower() == intf_name:
                        current_intf = intf
                        break
                continue

            if current_intf is not None:
                if cmd_stripped == "shutdown":
                    current_intf["status"] = "administratively down"
                    current_intf["protocol"] = "down"
                elif cmd_stripped == "no shutdown":
                    current_intf["status"] = "up"
                    current_intf["protocol"] = "up"

        return "% Demo mode: config applied"

    # ------------------------------------------------------------------
    # Health helpers
    # ------------------------------------------------------------------

    def get_health(self, device_name: str) -> dict:
        """Return a health-check dict for one device."""
        state = self.devices.get(device_name)
        if state is None:
            return {"device": device_name, "status": "unreachable", "error": "Not in demo inventory"}

        info = state["info"]
        total_mem = state["memory_used"] + state["memory_free"]
        mem_pct = round(state["memory_used"] / total_mem * 100, 1) if total_mem else 0

        intf_up = sum(1 for i in state["interfaces"] if i["status"] == "up")
        intf_total = len(state["interfaces"])

        return {
            "device": device_name,
            "status": "healthy",
            "platform": info.get("platform", "Unknown"),
            "uptime": state["uptime"],
            "cpu_percent": state["cpu"],
            "memory_percent": mem_pct,
            "interfaces_up": intf_up,
            "interfaces_total": intf_total,
            "bgp_peers_established": sum(
                1 for p in state["bgp_peers"] if p.get("state") == "Established"
            ),
            "ospf_adjacencies_full": sum(
                1 for a in state["ospf_adjacencies"] if "FULL" in a.get("state", "")
            ),
        }

    def get_all_health(self) -> list[dict]:
        """Return health-check dicts for every demo device."""
        return [self.get_health(name) for name in self.devices]

    def get_topology(self) -> list[dict]:
        """Return topology links from fixtures."""
        return list(self._topology_links)

    # ------------------------------------------------------------------
    # Show command renderers
    # ------------------------------------------------------------------

    def _show_version(self, name: str, state: dict) -> str:
        platform = state["version"]
        hostname = state["hostname"]
        uptime = state["uptime"]
        mem_total = state["memory_used"] + state["memory_free"]
        return (
            f"Cisco IOS XE Software, Version 17.13.01a\n"
            f"Cisco IOS Software [{platform}], Virtual XE Software "
            f"(X86_64_LINUX_IOSD-UNIVERSALK9-M), Version 17.13.1a\n"
            f"Technical Support: http://www.cisco.com/techsupport\n"
            f"Copyright (c) 1986-2025 by Cisco Systems, Inc.\n"
            f"\n"
            f"ROM: IOS-XE ROMMON\n"
            f"\n"
            f"{hostname} uptime is {uptime}\n"
            f"Uptime for this control processor is {uptime}\n"
            f"System returned to ROM by reload\n"
            f"System image file is \"bootflash:packages.conf\"\n"
            f"\n"
            f"cisco {platform} ({platform}) processor with {mem_total}K bytes of memory.\n"
            f"Processor board ID 9DEMO{name.upper()}\n"
            f"Router operating in autonomous mode.\n"
            f"3 Gigabit Ethernet interfaces\n"
            f"32768K bytes of non-volatile configuration memory.\n"
            f"8388608K bytes of physical memory.\n"
            f"\n"
            f"Configuration register is 0x2102"
        )

    def _show_ip_interface_brief(self, name: str, state: dict) -> str:
        header = (
            "Interface                  IP-Address      OK? Method Status"
            "                Protocol"
        )
        lines = [header]
        for intf in state["interfaces"]:
            ip = intf["ip_address"]
            status = intf["status"]
            proto = intf["protocol"]
            lines.append(
                f"{intf['name']:<27s}{ip:<16s}YES NVRAM  {status:<22s}{proto}"
            )
        return "\n".join(lines)

    def _show_ip_ospf_neighbor(self, name: str, state: dict) -> str:
        if not state["ospf_adjacencies"]:
            return ""
        header = (
            "Neighbor ID     Pri   State           Dead Time   Address         Interface"
        )
        lines = [header]
        for adj in state["ospf_adjacencies"]:
            lines.append(
                f"{adj['neighbor_id']:<16s}{adj['priority']:<6d}{adj['state']:<16s}"
                f"{adj['dead_time']:<12s}{adj['address']:<16s}{adj['interface']}"
            )
        return "\n".join(lines)

    def _show_ip_bgp_summary(self, name: str, state: dict) -> str:
        if not state["bgp_peers"]:
            return "% BGP not configured"

        loopback = state["info"].get("loopback", "0.0.0.0")  # nosec B104 — fallback IP, not a bind address
        header_block = (
            f"BGP router identifier {loopback}, local AS number 65000\n"
            f"BGP table version is 12, main routing table version 12\n"
            f"14 network entries using 3472 bytes of memory\n"
            f"14 path entries using 1904 bytes of memory\n"
            f"4/4 BGP path/bestpath attribute entries using 1152 bytes of memory\n"
            f"1 BGP AS-PATH entries using 24 bytes of memory\n"
            f"0 BGP route-map cache entries using 0 bytes of memory\n"
            f"0 BGP filter-list cache entries using 0 bytes of memory\n"
            f"BGP using 6552 total bytes of memory\n"
            f"BGP activity 14/0 prefixes, 14/0 paths, scan interval 60 secs\n"
            f"14 networks peaked at 10:23:45 Feb 15 2026\n"
            f"\n"
            f"Neighbor        V           AS MsgRcvd MsgSent   TblVer  InQ OutQ Up/Down  State/PfxRcd"
        )
        lines = [header_block]
        for peer in state["bgp_peers"]:
            neighbor = peer["neighbor"]
            remote_as = peer["remote_as"]
            pfx = peer["prefixes_received"]
            uptime = peer.get("uptime", "01:23:45")
            msg_rcvd = random.randint(1000, 9999)
            msg_sent = msg_rcvd + random.randint(-50, 50)
            pfx_display = str(pfx) if peer["state"] == "Established" else peer["state"]
            lines.append(
                f"{neighbor:<16s}4{remote_as:>12d}{msg_rcvd:>8d}{msg_sent:>8d}"
                f"{'12':>9s}    0    0 {uptime:<9s}{pfx_display:>8s}"
            )
        return "\n".join(lines)

    def _show_ip_route(self, name: str, state: dict) -> str:
        loopback = state["info"].get("loopback", "0.0.0.0")  # nosec B104 — fallback IP, not a bind address
        lines = [
            f"Codes: L - local, C - connected, S - static, R - RIP, M - mobile, B - BGP",
            f"       D - EIGRP, EX - EIGRP external, O - OSPF, IA - OSPF inter area",
            f"       N1 - OSPF NSSA external type 1, N2 - OSPF NSSA external type 2",
            f"       E1 - OSPF external type 1, E2 - OSPF external type 2, m - OMP",
            f"       n - NAT, Ni - NAT inside, No - NAT outside, Nd - NAT DIA",
            f"       i - IS-IS, su - IS-IS summary, L1 - IS-IS level-1, L2 - IS-IS level-2",
            f"       ia - IS-IS inter area, * - candidate default, U - per-user static route",
            f"       H - NHRP, G - NHRP registered, g - NHRP registration summary",
            f"       o - ODR, P - periodic downloaded static route, l - LISP",
            f"       a - application route, + - replicated route, % - next hop override",
            f"       & - replicated local route overriding next hop",
            f"",
            f"Gateway of last resort is not set",
            f"",
        ]

        # Connected routes from interfaces
        for intf in state["interfaces"]:
            ip = intf["ip_address"]
            if ip == "unassigned" or intf["status"] != "up":
                continue
            if "255.255.255.255" in intf.get("subnet_mask", ""):
                lines.append(f"      {loopback}/32 is directly connected, {intf['name']}")
            else:
                # Derive network from IP (simplistic)
                octets = ip.split(".")
                mask = intf.get("subnet_mask", "255.255.255.0")
                if mask == "255.255.255.252":
                    network = f"{octets[0]}.{octets[1]}.{octets[2]}.{int(octets[3]) & 252}"
                    prefix = f"{network}/30"
                else:
                    network = f"{octets[0]}.{octets[1]}.{octets[2]}.0"
                    prefix = f"{network}/24"
                lines.append(f"C        {prefix} is directly connected, {intf['name']}")
                lines.append(f"L        {ip}/32 is directly connected, {intf['name']}")

        # Add a few OSPF routes
        for adj in state["ospf_adjacencies"]:
            peer_ip = adj["address"]
            octets = peer_ip.split(".")
            network = f"{octets[0]}.{octets[1]}.{octets[2]}.0/24"
            lines.append(
                f"O        {network} [110/2] via {peer_ip}, 1d02h, {adj['interface']}"
            )

        return "\n".join(lines)

    def _show_running_config(self, name: str, state: dict) -> str:
        hostname = state["hostname"]
        lines = [
            "Building configuration...",
            "",
            "Current configuration : 2048 bytes",
            "!",
            f"hostname {hostname}",
            "!",
            "boot-start-marker",
            "boot-end-marker",
            "!",
            "no aaa new-model",
            "!",
        ]

        for intf in state["interfaces"]:
            lines.append(f"interface {intf['name']}")
            if intf.get("description"):
                lines.append(f" description {intf['description']}")
            ip = intf["ip_address"]
            mask = intf.get("subnet_mask", "")
            if ip != "unassigned" and mask:
                lines.append(f" ip address {ip} {mask}")
            if intf["status"] == "administratively down":
                lines.append(" shutdown")
            lines.append("!")

        if state["bgp_peers"]:
            lines.append("router bgp 65000")
            lines.append(f" bgp router-id {state['info'].get('loopback', '0.0.0.0')}")  # nosec B104
            lines.append(" bgp log-neighbor-changes")
            for peer in state["bgp_peers"]:
                lines.append(f" neighbor {peer['neighbor']} remote-as {peer['remote_as']}")
                lines.append(f" neighbor {peer['neighbor']} update-source Loopback0")
            lines.append("!")

        if state["ospf_adjacencies"]:
            lines.append("router ospf 1")
            lines.append(f" router-id {state['info'].get('loopback', '0.0.0.0')}")  # nosec B104
            for intf in state["interfaces"]:
                ip = intf["ip_address"]
                if ip != "unassigned":
                    lines.append(f" network {ip} 0.0.0.0 area 0")
            lines.append("!")

        lines.extend(["", "end"])
        return "\n".join(lines)

    def _show_ip_arp(self, name: str, state: dict) -> str:
        lines = [
            "Protocol  Address          Age (min)  Hardware Addr   Type   Interface"
        ]
        for intf in state["interfaces"]:
            ip = intf["ip_address"]
            if ip == "unassigned" or "Loopback" in intf["name"] or intf["name"] == "lo":
                continue
            mac = "demo.{:04x}.{:04x}".format(
                random.randint(0, 0xFFFF), random.randint(0, 0xFFFF)
            )
            lines.append(
                f"Internet  {ip:<17s}{random.randint(0, 240):<11d}{mac}  ARPA   {intf['name']}"
            )
        return "\n".join(lines)

    def _show_interfaces(self, name: str, state: dict) -> str:
        blocks = []
        for intf in state["interfaces"]:
            status = intf["status"]
            proto = intf["protocol"]
            ip = intf["ip_address"]
            mask = intf.get("subnet_mask", "")
            bw = intf["bandwidth"]
            mtu = intf["mtu"]
            in_pkt = intf["in_packets"]
            out_pkt = intf["out_packets"]
            block = (
                f"{intf['name']} is {status}, line protocol is {proto}\n"
                f"  Description: {intf.get('description', '')}\n"
                f"  Internet address is {ip}/{self._mask_to_prefix(mask)}\n"
                f"  MTU {mtu} bytes, BW {bw} Kbit/sec, DLY 10 usec,\n"
                f"     reliability 255/255, txload 1/255, rxload 1/255\n"
                f"  Encapsulation ARPA, loopback not set\n"
                f"  Keepalive set (10 sec)\n"
                f"  Full-duplex, 1000Mb/s, link type is auto, media type is Virtual\n"
                f"  output flow-control is unsupported, input flow-control is unsupported\n"
                f"  ARP type: ARPA, ARP Timeout 04:00:00\n"
                f"  Last input 00:00:01, output 00:00:01, output hang never\n"
                f"  Last clearing of \"show interface\" counters never\n"
                f"  Input queue: 0/375/0/0 (size/max/drops/flushes); Total output drops: 0\n"
                f"     5 minute input rate 1000 bits/sec, 1 packets/sec\n"
                f"     5 minute output rate 1000 bits/sec, 1 packets/sec\n"
                f"     {in_pkt} packets input, {in_pkt * 512} bytes, 0 no buffer\n"
                f"     {out_pkt} packets output, {out_pkt * 512} bytes, 0 underruns"
            )
            blocks.append(block)
        return "\n".join(blocks)

    def _show_inventory(self, name: str, state: dict) -> str:
        platform = state["version"]
        return (
            f'NAME: "Chassis", DESCR: "Cisco {platform} Chassis"\n'
            f"PID: {platform:<15s}, VID: V01, SN: 9DEMO{name.upper()}\n"
        )

    def _show_processes_cpu(self, name: str, state: dict) -> str:
        cpu = state["cpu"]
        return (
            f"CPU utilization for five seconds: {cpu:.0f}%/0%; one minute: {cpu:.0f}%; "
            f"five minutes: {cpu:.0f}%\n"
            f" PID Runtime(ms)     Invoked      uSecs   5Sec   1Min   5Min TTY Process\n"
            f"   1           0          12          0  0.00%  0.00%  0.00%   0 Chunk Manager\n"
            f"   2          10         380         26  0.00%  0.00%  0.00%   0 Load Meter\n"
            f"   3       18960       11587       1636  0.31%  0.24%  0.19%   0 IOSD ipc task"
        )

    def _ping(self, cmd: str, state: dict) -> str:
        match = re.search(r"ping\s+(\d+\.\d+\.\d+\.\d+)", cmd)
        if not match:
            return "% Incomplete command."
        target = match.group(1)

        # Check if target is any demo device IP (mgmt or loopback)
        known = False
        for dev in self._fixtures_devices.values():
            if target in (dev.get("host"), dev.get("loopback"), dev.get("lan_ip")):
                known = True
                break

        if known:
            return (
                f"Type escape sequence to abort.\n"
                f"Sending 5, 100-byte ICMP Echos to {target}, timeout is 2 seconds:\n"
                f"!!!!!\n"
                f"Success rate is 100 percent (5/5), round-trip min/avg/max = 1/2/4 ms"
            )
        else:
            return (
                f"Type escape sequence to abort.\n"
                f"Sending 5, 100-byte ICMP Echos to {target}, timeout is 2 seconds:\n"
                f".....\n"
                f"Success rate is 0 percent (0/5)"
            )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _mask_to_prefix(mask: str) -> int:
        """Convert dotted-decimal subnet mask to prefix length."""
        if not mask:
            return 32
        try:
            return sum(bin(int(o)).count("1") for o in mask.split("."))
        except (ValueError, AttributeError):
            return 32
