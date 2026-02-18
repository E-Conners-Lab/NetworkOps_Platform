"""Tests for multi-platform compliance parsing (FRR, SR Linux)."""

import pytest

from core.compliance_engine import ConfigParser, ConfigSection


class TestFRRParsing:
    """Tests for FRRouting config parsing."""

    SAMPLE_FRR_CONFIG = """
frr version 8.5
frr defaults traditional
hostname edge1
log syslog informational
!
router bgp 65100
 bgp router-id 10.255.0.2
 neighbor 172.20.20.1 remote-as 65001
 neighbor 172.20.20.1 password secret123
 !
 address-family ipv4 unicast
  redistribute connected
 exit-address-family
!
router ospf
 ospf router-id 10.255.0.2
 network 10.255.0.0/24 area 0
!
interface eth0
 ip address 172.20.20.5/24
!
interface lo
 ip address 10.255.0.2/32
!
ip prefix-list ALLOW_DEFAULT seq 5 permit 0.0.0.0/0
!
route-map IMPORT permit 10
 match ip address prefix-list ALLOW_DEFAULT
!
""".strip()

    def test_parse_frr_router_sections(self):
        sections = ConfigParser.parse(self.SAMPLE_FRR_CONFIG, "frr")
        router_sections = [s for s in sections if s.name == "router"]
        assert len(router_sections) >= 2  # bgp + ospf

    def test_parse_frr_interface_sections(self):
        sections = ConfigParser.parse(self.SAMPLE_FRR_CONFIG, "frr")
        intf_sections = [s for s in sections if s.name == "interface"]
        assert len(intf_sections) >= 2  # eth0 + lo

    def test_parse_frr_prefix_list(self):
        sections = ConfigParser.parse(self.SAMPLE_FRR_CONFIG, "frr")
        pl_sections = [s for s in sections if s.name == "prefix-list"]
        assert len(pl_sections) >= 1

    def test_parse_frr_route_map(self):
        sections = ConfigParser.parse(self.SAMPLE_FRR_CONFIG, "frr")
        rm_sections = [s for s in sections if s.name == "route-map"]
        assert len(rm_sections) >= 1

    def test_frr_section_contains_lines(self):
        sections = ConfigParser.parse(self.SAMPLE_FRR_CONFIG, "frr")
        bgp_sections = [s for s in sections if s.name == "router"]
        # At least one router section should have child lines
        has_content = any(len(s.lines) > 1 for s in bgp_sections)
        assert has_content


class TestSRLinuxParsing:
    """Tests for Nokia SR Linux config parsing."""

    SAMPLE_SRLINUX_CONFIG = """
/interface ethernet-1/1 admin-state enable
/interface ethernet-1/1 subinterface 0 ipv4 admin-state enable
/interface ethernet-1/1 subinterface 0 ipv4 address 10.0.0.1/30
/interface lo0 admin-state enable
/interface lo0 subinterface 0 ipv4 address 10.10.10.10/32
/network-instance default type default
/network-instance default interface ethernet-1/1.0
/network-instance default interface lo0.0
/network-instance default protocols ospf instance default area 0.0.0.0
/routing-policy policy EXPORT-LOOPBACKS statement 10 match protocol local
/routing-policy policy EXPORT-LOOPBACKS statement 10 action policy-result accept
/system name host-name spine1
/system ntp server 10.0.0.254
/system logging network-instance mgmt
""".strip()

    def test_parse_srlinux_interfaces(self):
        sections = ConfigParser.parse(self.SAMPLE_SRLINUX_CONFIG, "srlinux")
        intf_sections = [s for s in sections if s.name == "interface"]
        assert len(intf_sections) >= 1

    def test_parse_srlinux_network_instance(self):
        sections = ConfigParser.parse(self.SAMPLE_SRLINUX_CONFIG, "srlinux")
        ni_sections = [s for s in sections if s.name == "network-instance"]
        assert len(ni_sections) >= 1

    def test_parse_srlinux_routing_policy(self):
        sections = ConfigParser.parse(self.SAMPLE_SRLINUX_CONFIG, "srlinux")
        rp_sections = [s for s in sections if s.name == "routing-policy"]
        assert len(rp_sections) >= 1

    def test_parse_srlinux_system(self):
        sections = ConfigParser.parse(self.SAMPLE_SRLINUX_CONFIG, "srlinux")
        sys_sections = [s for s in sections if s.name == "system"]
        assert len(sys_sections) >= 1


class TestPlatformMap:
    """Tests for platform mapping."""

    def test_cisco_xe_maps_to_cisco_ios(self):
        assert ConfigParser.PLATFORM_MAP["cisco_xe"] == "cisco_ios"

    def test_containerlab_frr_maps_to_frr(self):
        assert ConfigParser.PLATFORM_MAP["containerlab_frr"] == "frr"

    def test_containerlab_srlinux_maps_to_srlinux(self):
        assert ConfigParser.PLATFORM_MAP["containerlab_srlinux"] == "srlinux"

    def test_frr_patterns_exist(self):
        assert "frr" in ConfigParser.SECTION_PATTERNS
        pattern_names = [name for _, name in ConfigParser.SECTION_PATTERNS["frr"]]
        assert "router" in pattern_names
        assert "interface" in pattern_names
        assert "prefix-list" in pattern_names

    def test_srlinux_patterns_exist(self):
        assert "srlinux" in ConfigParser.SECTION_PATTERNS
        pattern_names = [name for _, name in ConfigParser.SECTION_PATTERNS["srlinux"]]
        assert "interface" in pattern_names
        assert "network-instance" in pattern_names
        assert "system" in pattern_names


class TestCiscoParsingUnchanged:
    """Verify Cisco IOS parsing still works correctly."""

    SAMPLE_CISCO_CONFIG = """
!
service password-encryption
service timestamps log datetime msec
!
hostname R1
!
aaa new-model
aaa authentication login default local
!
interface Loopback0
 ip address 198.51.100.1 255.255.255.255
!
interface GigabitEthernet1
 ip address 10.255.255.11 255.255.255.0
 no shutdown
!
router ospf 1
 router-id 198.51.100.1
 network 198.51.100.0 0.0.0.255 area 0
!
logging buffered 16384
!
ntp authenticate
!
""".strip()

    def test_cisco_sections_still_parse(self):
        sections = ConfigParser.parse(self.SAMPLE_CISCO_CONFIG, "cisco_ios")
        section_names = {s.name for s in sections}
        assert "interface" in section_names
        assert "router" in section_names

    def test_cisco_global_config(self):
        global_lines = ConfigParser.get_global_config(self.SAMPLE_CISCO_CONFIG)
        global_text = "\n".join(global_lines)
        # "hostname" is a global config line (not matched by any section pattern)
        assert "hostname R1" in global_text
        # "aaa" lines match the aaa section pattern, so they won't be global
        # "service" lines match the service section pattern, so they won't be global
        # Verify we get some global lines
        assert len(global_lines) > 0
