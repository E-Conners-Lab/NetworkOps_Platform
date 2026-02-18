"""Tests for IOS-XE config parser, template rendering, and round-trip."""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scripts.collect_iosxe_configs import parse_running_config

# R6 backup config — simplest router (218 lines, OSPF only, no BGP/DMVPN)
R6_RAW = """\
Building configuration...

Current configuration : 6480 bytes
!
! Last configuration change at 06:37:08 UTC Wed Dec 31 2025 by admin
!
version 17.13
service tcp-keepalives-in
service tcp-keepalives-out
service timestamps debug datetime msec
service timestamps log datetime msec
service password-encryption
platform qfp utilization monitor load 80
platform punt-keepalive disable-kernel-core
platform sslvpn use-pd
platform console serial
!
hostname R6
!
boot-start-marker
boot-end-marker
!
!
logging buffered 16384 informational
aaa new-model
!
!
aaa authentication login default local
aaa authorization exec default local
!
!
aaa session-id common
!
!
!
!
!
!
!
!
!
!
!
!
ip domain name lab.local
!
!
!
login on-success log
!
!
subscriber templating
!
pae
!
!
crypto pki trustpoint SLA-TrustPoint
 enrollment pkcs12
 revocation-check crl
 hash sha256
!
crypto pki trustpoint TP-self-signed-4012323912
 enrollment selfsigned
 subject-name cn=IOS-Self-Signed-Certificate-4012323912
 revocation-check none
 rsakeypair TP-self-signed-4012323912
 hash sha256
!
!
crypto pki certificate chain SLA-TrustPoint
 certificate ca 01
  30820321 30820209 A0030201 FAKECERT
  \tquit
crypto pki certificate chain TP-self-signed-4012323912
 certificate self-signed 01
  30820330 30820218 A0030201 FAKECERT
  \tquit
!
!
license udi pid C8000V sn 9WRO3IGUNAF
memory free low-watermark processor 225161
diagnostic bootup level minimal
!
!
!
enable secret 9 $9$FAKEHASH
!
username admin privilege 15 secret 9 $9$FAKEHASH
!
redundancy
!
!
cdp run
!
lldp run
!
!
!
!
!
interface Loopback0
 ip address 6.6.6.6 255.255.255.255
 ip ospf 1 area 0
!
interface GigabitEthernet1
 no ip address
 negotiation auto
!
interface GigabitEthernet2
 description To R2 Gi5
 ip address 10.0.26.2 255.255.255.252
 ip ospf network point-to-point
 ip ospf 1 area 0
 negotiation auto
!
interface GigabitEthernet3
 no ip address
 negotiation auto
!
interface GigabitEthernet4
 ip dhcp client client-id ascii 9WRO3IGUNAF
 ip address 10.255.255.36 255.255.255.0
 negotiation auto
!
router ospf 1
 router-id 6.6.6.6
 passive-interface Loopback0
!
ip forward-protocol nd
!
no ip http server
ip http authentication local
no ip http secure-server
ip http client source-interface GigabitEthernet4
ip route 0.0.0.0 0.0.0.0 10.255.255.1
ip ssh bulk-mode 131072
!
!
!
!
!
!
!
control-plane
!
banner motd ^C
******************************************************************
*  AUTHORIZED ACCESS ONLY - NetworkOps Managed Device           *
******************************************************************
^C
!
line con 0
 stopbits 1
line aux 0
line vty 0 4
 transport input ssh
line vty 5 15
 transport input ssh
!
ntp authenticate
!
!
!
!
!
!
netconf-yang
end"""


class TestParserR6:
    """Test parser against the simplest router config (R6)."""

    @pytest.fixture(autouse=True)
    def parsed(self):
        self.result = parse_running_config(R6_RAW)

    def test_ospf_process_id(self):
        assert self.result["ospf_process_id"] == 1

    def test_ospf_enabled(self):
        assert self.result["ospf_enabled"] is True

    def test_ospf_passive_interfaces(self):
        assert self.result["ospf_passive_interfaces"] == ["Loopback0"]

    def test_static_routes(self):
        assert len(self.result["static_routes"]) == 1
        route = self.result["static_routes"][0]
        assert route["prefix"] == "0.0.0.0"
        assert route["mask"] == "0.0.0.0"
        assert route["next_hop"] == "10.255.255.1"

    def test_preamble_starts_with_version(self):
        assert self.result["iosxe_preamble"].startswith("version 17.13")

    def test_preamble_does_not_contain_interface(self):
        assert "interface " not in self.result["iosxe_preamble"]

    def test_preamble_contains_hostname(self):
        assert "hostname R6" in self.result["iosxe_preamble"]

    def test_ntp_authenticate(self):
        assert self.result["ntp_config"]["authenticate"] is True

    def test_no_bgp(self):
        assert self.result["bgp_asn"] is None
        assert self.result["bgp_peers"] == []

    def test_interfaces_count(self):
        assert len(self.result["interfaces_parsed"]) == 5

    def test_loopback0_ip(self):
        lo = next(i for i in self.result["interfaces_parsed"] if i["name"] == "Loopback0")
        assert lo["ip_address"] == "6.6.6.6"
        assert lo["netmask"] == "255.255.255.255"

    def test_gi1_no_ip(self):
        gi1 = next(i for i in self.result["interfaces_parsed"] if i["name"] == "GigabitEthernet1")
        assert gi1["no_ip_address"] is True
        assert gi1["ip_address"] is None

    def test_gi2_description(self):
        gi2 = next(i for i in self.result["interfaces_parsed"] if i["name"] == "GigabitEthernet2")
        assert gi2["description"] == "To R2 Gi5"

    def test_gi4_dhcp_client(self):
        # DHCP client-id is now stored in iosxe_interface_extra as an extra line
        extra = self.result["iosxe_interface_extra"].get("GigabitEthernet4", [])
        assert any("ip dhcp client client-id ascii 9WRO3IGUNAF" in line for line in extra)

    def test_ospf_per_interface(self):
        # Loopback0 and Gi2 both have ip ospf 1 area 0
        ospf_ifs = [oi for oi in self.result["ospf_interfaces"] if "name" in oi]
        names = {oi["name"] for oi in ospf_ifs}
        assert "Loopback0" in names
        assert "GigabitEthernet2" in names

    def test_ospf_network_type(self):
        ospf_ifs = [oi for oi in self.result["ospf_interfaces"] if "name" in oi]
        gi2 = next(oi for oi in ospf_ifs if oi["name"] == "GigabitEthernet2")
        assert gi2["network_type"] == "point-to-point"

    def test_postamble_contains_control_plane(self):
        assert "control-plane" in self.result["iosxe_postamble"]

    def test_postamble_contains_banner(self):
        assert "banner motd" in self.result["iosxe_postamble"]

    def test_postamble_contains_netconf(self):
        assert "netconf-yang" in self.result["iosxe_postamble"]

    def test_no_routing_extra(self):
        assert self.result["iosxe_routing_extra"] == ""

    def test_interface_extra_empty_for_loopback(self):
        # Loopback0 has no extra lines (ip ospf is parsed structurally)
        assert "Loopback0" not in self.result["iosxe_interface_extra"]


# R7 minimal config — stub OSPF area, DHCP management, no BGP
R7_RAW = """\
Building configuration...

Current configuration : 6295 bytes
!
! Last configuration change at 05:24:36 UTC Wed Dec 31 2025 by admin
!
version 17.13
service tcp-keepalives-in
service tcp-keepalives-out
service timestamps debug datetime msec
service timestamps log datetime msec
service password-encryption
platform qfp utilization monitor load 80
platform punt-keepalive disable-kernel-core
platform sslvpn use-pd
platform console serial
!
hostname R7
!
boot-start-marker
boot-end-marker
!
!
logging buffered 16384 informational
no logging console
aaa new-model
!
!
aaa authentication login default local
aaa authorization exec default local
!
!
aaa session-id common
!
!
!
!
!
!
!
!
!
!
!
!
!
!
!
login on-success log
!
!
subscriber templating
!
pae
!
!
crypto pki trustpoint SLA-TrustPoint
 enrollment pkcs12
 revocation-check crl
 hash sha256
!
crypto pki trustpoint TP-self-signed-2012294885
 enrollment selfsigned
 subject-name cn=IOS-Self-Signed-Certificate-2012294885
 revocation-check none
 rsakeypair TP-self-signed-2012294885
 hash sha256
!
!
crypto pki certificate chain SLA-TrustPoint
 certificate ca 01
  30820321 30820209 A0030201 FAKECERT
  \tquit
crypto pki certificate chain TP-self-signed-2012294885
 certificate self-signed 01
  30820330 30820218 A0030201 FAKECERT
  \tquit
!
!
license udi pid C8000V sn 9PJFBH03YKU
memory free low-watermark processor 225161
diagnostic bootup level minimal
!
!
!
enable secret 9 $9$FAKEHASH
!
username admin privilege 15 secret 9 $9$FAKEHASH
!
redundancy
!
!
cdp run
!
lldp run
!
!
!
!
!
interface Loopback0
 ip address 7.7.7.7 255.255.255.255
 ip ospf 1 area 4
!
interface GigabitEthernet1
 ip dhcp client client-id ascii 9PJFBH03YKU
 ip address dhcp
 negotiation auto
!
interface GigabitEthernet2
 description Link to R4 Gi1
 ip address 10.0.47.2 255.255.255.252
 ip ospf network point-to-point
 ip ospf 1 area 4
 negotiation auto
 cdp enable
!
interface GigabitEthernet3
 no ip address
 shutdown
 negotiation auto
!
interface GigabitEthernet4
 no ip address
 shutdown
 negotiation auto
!
router ospf 1
 router-id 7.7.7.7
 area 4 stub
!
ip forward-protocol nd
!
no ip http server
ip http authentication local
ip http secure-server
ip http client source-interface GigabitEthernet1
ip ssh bulk-mode 131072
!
!
!
!
!
!
!
control-plane
!
banner login ^C AUTHORIZED ACCESS ONLY - All activity is monitored and logged ^C
!
line con 0
 exec-timeout 0 0
 stopbits 1
line aux 0
line vty 0 4
 exec-timeout 0 0
 transport input ssh
!
ntp authenticate
!
!
!
!
!
!
netconf-yang
end"""


class TestParserR7:
    """Test R7 — stub area, DHCP Gi1, shutdown interfaces."""

    @pytest.fixture(autouse=True)
    def parsed(self):
        self.result = parse_running_config(R7_RAW)

    def test_ospf_area_stub(self):
        assert self.result["ospf_areas"] == {"4": "stub"}

    def test_gi1_dhcp(self):
        gi1 = next(i for i in self.result["interfaces_parsed"] if i["name"] == "GigabitEthernet1")
        assert gi1["dhcp"] is True
        # DHCP client-id is now stored in iosxe_interface_extra as an extra line
        extra = self.result["iosxe_interface_extra"].get("GigabitEthernet1", [])
        assert any("ip dhcp client client-id ascii 9PJFBH03YKU" in line for line in extra)

    def test_gi3_shutdown(self):
        gi3 = next(i for i in self.result["interfaces_parsed"] if i["name"] == "GigabitEthernet3")
        assert gi3["shutdown"] is True
        assert gi3["no_ip_address"] is True

    def test_gi2_cdp_in_extra(self):
        extra = self.result["iosxe_interface_extra"].get("GigabitEthernet2", [])
        assert "cdp enable" in extra

    def test_no_static_routes(self):
        # R7 has no static routes
        assert self.result["static_routes"] == []


# BGP config fragment for testing BGP parsing
BGP_CONFIG = """\
version 17.13
hostname R3
!
interface Loopback0
 ip address 3.3.3.3 255.255.255.255
!
interface GigabitEthernet2
 ip address 10.0.13.2 255.255.255.252
 negotiation auto
!
router ospf 1
 router-id 3.3.3.3
 passive-interface GigabitEthernet3
 network 10.0.13.0 0.0.0.3 area 0
 bfd all-interfaces
!
router bgp 65000
 bgp router-id 3.3.3.3
 bgp log-neighbor-changes
 no bgp default ipv4-unicast
 neighbor 1.1.1.1 remote-as 65000
 neighbor 1.1.1.1 update-source Loopback0
 neighbor 172.20.20.3 remote-as 65100
 neighbor 172.20.20.3 description edge1-Containerlab
 neighbor 172.20.20.3 ebgp-multihop 5
 neighbor 172.20.20.3 update-source GigabitEthernet4
 !
 address-family ipv4
  network 3.3.3.3 mask 255.255.255.255
  network 10.3.0.0 mask 255.255.255.0
  neighbor 1.1.1.1 activate
  neighbor 172.20.20.3 activate
 exit-address-family
 !
 address-family ipv6
  network 2001:DB8::3/128
  network 2001:DB8:3::/64
  neighbor 1.1.1.1 activate
 exit-address-family
!
ip route 0.0.0.0 0.0.0.0 10.255.255.1
ip route 10.100.1.0 255.255.255.0 172.20.20.4 250
!
ntp authenticate
ntp source Loopback0
ntp server 1.1.1.1 source Loopback0
ntp server 10.255.255.1
ntp server pool.ntp.org
!
control-plane
!
end"""


class TestParserBGP:
    """Test BGP parsing from R3-like config."""

    @pytest.fixture(autouse=True)
    def parsed(self):
        self.result = parse_running_config(BGP_CONFIG)

    def test_bgp_asn(self):
        assert self.result["bgp_asn"] == 65000

    def test_bgp_no_default_ipv4(self):
        assert self.result["bgp_no_default_ipv4"] is True

    def test_bgp_peers(self):
        peers = self.result["bgp_peers"]
        assert len(peers) == 2
        ibgp = next(p for p in peers if p["neighbor"] == "1.1.1.1")
        assert ibgp["remote_as"] == 65000
        assert ibgp["update_source"] == "Loopback0"
        ebgp = next(p for p in peers if p["neighbor"] == "172.20.20.3")
        assert ebgp["remote_as"] == 65100
        assert ebgp["ebgp_multihop"] == 5
        assert ebgp["description"] == "edge1-Containerlab"

    def test_bgp_address_families(self):
        afs = self.result["bgp_address_families"]
        assert len(afs) == 2
        ipv4_af = next(af for af in afs if af["afi"] == "ipv4")
        assert len(ipv4_af["networks"]) == 2
        assert ipv4_af["networks"][0]["prefix"] == "3.3.3.3"
        assert ipv4_af["networks"][0]["mask"] == "255.255.255.255"
        assert len(ipv4_af["neighbors"]) == 2

    def test_ospf_bfd(self):
        assert self.result["ospf_bfd"] is True

    def test_ospf_network_statements(self):
        net_stmts = [oi for oi in self.result["ospf_interfaces"] if "network" in oi]
        assert len(net_stmts) == 1
        assert net_stmts[0]["network"] == "10.0.13.0"
        assert net_stmts[0]["wildcard"] == "0.0.0.3"
        assert net_stmts[0]["area"] == "0"

    def test_static_routes_with_ad(self):
        routes = self.result["static_routes"]
        ad_route = next(r for r in routes if r["prefix"] == "10.100.1.0")
        assert ad_route["ad"] == 250
        assert ad_route["mask"] == "255.255.255.0"
        assert ad_route["next_hop"] == "172.20.20.4"

    def test_ntp_servers(self):
        ntp = self.result["ntp_config"]
        assert ntp["source"] == "Loopback0"
        assert ntp["authenticate"] is True
        assert len(ntp["servers"]) == 3
        assert ntp["servers"][0]["address"] == "1.1.1.1"
        assert ntp["servers"][0]["source"] == "Loopback0"


class TestTemplateRender:
    """Test that the Jinja2 template renders correctly from parsed data."""

    def test_render_r6_round_trip(self):
        """Parse R6, build context, render template, verify key sections."""
        import jinja2

        parsed = parse_running_config(R6_RAW)

        # Build context matching what generate_configs.py would produce
        context = {
            "iosxe_preamble": parsed["iosxe_preamble"],
            "iosxe_postamble": parsed["iosxe_postamble"],
            "iosxe_routing_extra": parsed["iosxe_routing_extra"],
            "interfaces": [],
            "router_id": "6.6.6.6",
            "ospf_enabled": parsed["ospf_enabled"],
            "ospf_process_id": parsed["ospf_process_id"],
            "ospf_passive_interfaces": parsed["ospf_passive_interfaces"],
            "ospf_networks": [oi for oi in parsed["ospf_interfaces"] if "network" in oi],
            "ospf_bfd": parsed["ospf_bfd"],
            "ospf_areas": parsed["ospf_areas"],
            "ospf_redistribute": parsed["ospf_redistribute"],
            "bgp_asn": parsed["bgp_asn"],
            "bgp_peers": parsed["bgp_peers"],
            "bgp_peer_groups": parsed["bgp_peer_groups"],
            "bgp_address_families": parsed["bgp_address_families"],
            "bgp_no_default_ipv4": parsed["bgp_no_default_ipv4"],
            "static_routes": parsed["static_routes"],
            "ntp_config": parsed["ntp_config"],
        }

        # Build interfaces from parsed data
        for intf in parsed["interfaces_parsed"]:
            ospf_process_id = None
            ospf_area = None
            ospf_network_type = None
            for oi in parsed["ospf_interfaces"]:
                if oi.get("name") == intf["name"]:
                    ospf_process_id = oi.get("process_id")
                    ospf_area = oi.get("area")
                    ospf_network_type = oi.get("network_type")
                    break

            # Split extra_lines like the real generator does
            raw_extra = list(parsed["iosxe_interface_extra"].get(intf["name"], []))
            dhcp_client_id = None
            vrf = intf["vrf"]
            ip_extra_lines = []
            extra_lines = []
            for line in raw_extra:
                if line.startswith("ip dhcp client client-id "):
                    dhcp_client_id = line.split()[-1]
                elif line.startswith("vrf forwarding "):
                    vrf = line.split()[-1]
                elif line.startswith("ip ") or line.startswith("no ip "):
                    ip_extra_lines.append(line)
                else:
                    extra_lines.append(line)

            context["interfaces"].append({
                "name": intf["name"],
                "description": intf["description"],
                "ip_address": intf["ip_address"],
                "netmask": intf["netmask"],
                "no_ip_address": intf["no_ip_address"],
                "shutdown": intf["shutdown"],
                "negotiation_auto": intf["negotiation_auto"],
                "dhcp": intf["dhcp"],
                "dhcp_client_id": dhcp_client_id,
                "vrf": vrf,
                "ospf_process_id": ospf_process_id,
                "ospf_area": ospf_area,
                "ospf_network_type": ospf_network_type,
                "ip_extra_lines": ip_extra_lines,
                "extra_lines": extra_lines,
            })

        template_dir = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "templates", "iosxe",
        )
        env = jinja2.Environment(
            loader=jinja2.FileSystemLoader(template_dir),
            trim_blocks=True,
            lstrip_blocks=True,
            keep_trailing_newline=False,
        )

        rendered = env.get_template("running-config.j2").render(**context)

        # Verify key sections are present
        assert "version 17.13" in rendered
        assert "hostname R6" in rendered
        assert "interface Loopback0" in rendered
        assert "ip address 6.6.6.6 255.255.255.255" in rendered
        assert "interface GigabitEthernet2" in rendered
        assert "description To R2 Gi5" in rendered
        assert "ip ospf network point-to-point" in rendered
        assert "ip ospf 1 area 0" in rendered
        assert "router ospf 1" in rendered
        assert "router-id 6.6.6.6" in rendered
        assert "passive-interface Loopback0" in rendered
        assert "ip route 0.0.0.0 0.0.0.0 10.255.255.1" in rendered
        assert "ntp authenticate" in rendered
        assert "netconf-yang" in rendered
        assert rendered.strip().endswith("end")

    def test_frr_template_ignores_cisco_keys(self):
        """Verify FRR templates still work with extended bgp_peers schema."""
        import jinja2

        frr_dir = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "templates", "frr",
        )
        env = jinja2.Environment(
            loader=jinja2.FileSystemLoader(frr_dir),
            trim_blocks=True,
            lstrip_blocks=True,
            keep_trailing_newline=False,
        )

        # Context with Cisco-extended fields (mask, ad, peer_group)
        context = {
            "hostname": "test",
            "router_id": "10.0.0.1",
            "static_routes": [
                {"prefix": "0.0.0.0/0", "next_hop": "10.0.0.1", "mask": "0.0.0.0", "ad": 250},
            ],
            "interfaces": [],
            "bgp_asn": 65000,
            "bgp_peers": [
                {"neighbor": "10.0.0.2", "remote_as": 65001, "peer_group": "IBGP", "description": "test"},
            ],
            "bgp_networks": [{"prefix": "10.0.0.0/24"}],
            "ospf_enabled": False,
            "ospf_networks": [],
            "ospf_redistribute": [],
            "frr_extra_config": "",
        }

        # This should not raise — extra keys should be silently ignored
        rendered = env.get_template("frr.conf.j2").render(**context)
        assert "router bgp 65000" in rendered
        assert "neighbor 10.0.0.2 remote-as 65001" in rendered


class TestParserRoutingExtra:
    """Test that non-OSPF/BGP routing blocks go to routing_extra."""

    EIGRP_CONFIG = """\
version 17.13
hostname R1
!
interface Loopback0
 ip address 1.1.1.1 255.255.255.255
!
interface GigabitEthernet1
 ip address 10.0.12.1 255.255.255.252
 negotiation auto
!
router eigrp DMVPN
 !
 address-family ipv4 unicast autonomous-system 100
  !
  topology base
  exit-af-topology
  network 10.1.0.0 0.0.0.255
  network 172.16.0.0 0.0.0.255
 exit-address-family
!
router ospfv3 1
 router-id 1.1.1.1
 !
 address-family ipv6 unicast
 exit-address-family
!
router ospf 1
 router-id 1.1.1.1
!
ip route 0.0.0.0 0.0.0.0 10.255.255.1
!
control-plane
!
end"""

    def test_eigrp_in_routing_extra(self):
        result = parse_running_config(self.EIGRP_CONFIG)
        assert "router eigrp DMVPN" in result["iosxe_routing_extra"]
        assert "network 10.1.0.0 0.0.0.255" in result["iosxe_routing_extra"]

    def test_ospfv3_in_routing_extra(self):
        result = parse_running_config(self.EIGRP_CONFIG)
        assert "router ospfv3 1" in result["iosxe_routing_extra"]

    def test_ospf_not_in_routing_extra(self):
        result = parse_running_config(self.EIGRP_CONFIG)
        # "router ospfv3" is expected in routing_extra, but "router ospf 1" should NOT be
        for line in result["iosxe_routing_extra"].splitlines():
            stripped = line.strip()
            if stripped.startswith("router ospf"):
                assert stripped.startswith("router ospfv3"), (
                    f"Found 'router ospf' (not ospfv3) in routing_extra: {stripped}"
                )
