"""
Tests for NTC-Templates parser integration.
"""

import pytest
from unittest.mock import patch, MagicMock

from core.ntc_parser import (
    NTCParser, ParseResult, NTCTemplateInfo,
    PLATFORM_MAP, get_ntc_parser
)


class TestPlatformMapping:
    """Tests for platform name mapping"""

    def test_cisco_platforms(self):
        """Cisco platforms should map correctly"""
        assert PLATFORM_MAP["cisco_xe"] == "cisco_ios"
        assert PLATFORM_MAP["cisco_ios"] == "cisco_ios"
        assert PLATFORM_MAP["cisco_nxos"] == "cisco_nxos"

    def test_arista_platform(self):
        """Arista should map to arista_eos"""
        assert PLATFORM_MAP["arista_eos"] == "arista_eos"
        assert PLATFORM_MAP["arista"] == "arista_eos"

    def test_juniper_platform(self):
        """Juniper should map to juniper_junos"""
        assert PLATFORM_MAP["juniper_junos"] == "juniper_junos"
        assert PLATFORM_MAP["juniper"] == "juniper_junos"

    def test_frrouting_maps_to_cisco(self):
        """FRRouting uses Cisco-like output"""
        assert PLATFORM_MAP["frrouting"] == "cisco_ios"
        assert PLATFORM_MAP["frr"] == "cisco_ios"

    def test_nokia_platforms(self):
        """Nokia platforms should map correctly"""
        assert PLATFORM_MAP["nokia_sros"] == "nokia_sros"
        assert PLATFORM_MAP["nokia_srlinux"] == "nokia_srlinux"


class TestParseResult:
    """Tests for ParseResult dataclass"""

    def test_successful_result(self):
        """Create successful parse result"""
        result = ParseResult(
            success=True,
            parser="ntc",
            data=[{"interface": "Gi1", "status": "up"}],
            command="show ip interface brief",
            platform="cisco_ios"
        )

        assert result.success is True
        assert result.parser == "ntc"
        assert len(result.data) == 1
        assert result.error is None

    def test_failed_result(self):
        """Create failed parse result"""
        result = ParseResult(
            success=False,
            parser="ntc",
            data=None,
            command="show something",
            platform="unknown",
            error="No template found"
        )

        assert result.success is False
        assert result.error == "No template found"

    def test_to_dict(self):
        """Convert result to dictionary"""
        result = ParseResult(
            success=True,
            parser="ntc",
            data={"test": "data"},
            command="show version",
            platform="cisco_ios"
        )

        d = result.to_dict()

        assert d["success"] is True
        assert d["parser"] == "ntc"
        assert d["command"] == "show version"
        assert d["platform"] == "cisco_ios"


class TestNTCParser:
    """Tests for NTCParser class"""

    def test_get_platform_mapping(self):
        """Platform should map correctly"""
        parser = NTCParser()

        assert parser.get_platform("cisco_xe") == "cisco_ios"
        assert parser.get_platform("arista_eos") == "arista_eos"
        assert parser.get_platform("unknown") == "unknown"

    def test_is_available(self):
        """Should detect ntc-templates availability"""
        parser = NTCParser()
        # Should be True since we installed it
        assert parser.is_available is True

    @patch('core.feature_flags.is_enabled')
    def test_parse_disabled(self, mock_enabled):
        """Parse should fail when feature disabled"""
        mock_enabled.return_value = False
        parser = NTCParser()

        result = parser.parse(
            "show ip interface brief",
            "some output",
            "cisco_ios"
        )

        assert result.success is False
        assert "disabled" in result.error.lower()

    @patch('core.ntc_parser.is_enabled')
    def test_parse_cisco_interface_brief(self, mock_enabled):
        """Parse Cisco show ip interface brief"""
        mock_enabled.return_value = True
        parser = NTCParser()

        output = """
Interface              IP-Address      OK? Method Status                Protocol
GigabitEthernet1       10.0.12.1       YES NVRAM  up                    up
GigabitEthernet2       10.0.13.1       YES NVRAM  up                    up
GigabitEthernet3       10.1.0.1        YES NVRAM  up                    up
GigabitEthernet4       10.255.255.11   YES NVRAM  up                    up
Loopback0              198.51.100.1         YES NVRAM  up                    up
"""

        result = parser.parse(
            "show ip interface brief",
            output,
            "cisco_ios"
        )

        assert result.success is True
        assert result.parser == "ntc"
        assert len(result.data) >= 4

    @patch('core.ntc_parser.is_enabled')
    def test_parse_ospf_neighbors(self, mock_enabled):
        """Parse OSPF neighbor output"""
        mock_enabled.return_value = True
        parser = NTCParser()

        output = """
Neighbor ID     Pri   State           Dead Time   Address         Interface
198.51.100.2           1   FULL/DR         00:00:35    10.0.12.2       GigabitEthernet1
198.51.100.3           1   FULL/BDR        00:00:33    10.0.13.2       GigabitEthernet2
"""

        result = parser.parse(
            "show ip ospf neighbor",
            output,
            "cisco_ios"
        )

        assert result.success is True
        assert len(result.data) >= 2


class TestNTCParserRegexFallback:
    """Tests for regex fallback parsing"""

    def test_interface_brief_regex(self):
        """Regex should parse interface brief"""
        parser = NTCParser()

        output = """
GigabitEthernet1       10.0.12.1       YES NVRAM  up                    up
GigabitEthernet2       10.0.13.1       YES NVRAM  administratively down down
"""

        result = parser._parse_interface_brief(output)

        assert result is not None
        assert len(result) == 2
        assert result[0]["interface"] == "GigabitEthernet1"
        assert result[0]["ip_address"] == "10.0.12.1"
        assert result[0]["status"] == "up"

    def test_bgp_summary_regex(self):
        """Regex should parse BGP summary"""
        parser = NTCParser()

        output = """
Neighbor        V           AS MsgRcvd MsgSent   TblVer  InQ OutQ Up/Down  State/PfxRcd
10.0.0.2        4        65001     100     100        5    0    0 00:30:00       10
10.0.0.3        4        65002     200     200        5    0    0 01:00:00 Active
"""

        result = parser._parse_bgp_summary(output)

        assert result is not None
        assert len(result) == 2
        assert result[0]["neighbor"] == "10.0.0.2"
        assert result[0]["remote_as"] == 65001
        assert result[0]["state"] == "Established"  # Has prefix count
        assert result[1]["state"] == "Active"  # Not established

    def test_ospf_neighbors_regex(self):
        """Regex should parse OSPF neighbors"""
        parser = NTCParser()

        output = """
Neighbor ID     Pri   State           Dead Time   Address         Interface
198.51.100.2           1   FULL/DR         00:00:35    10.0.12.2       GigabitEthernet1
198.51.100.3           1   FULL/BDR        00:00:33    10.0.13.2       GigabitEthernet2
"""

        result = parser._parse_ospf_neighbors(output)

        assert result is not None
        assert len(result) == 2
        assert result[0]["neighbor_id"] == "198.51.100.2"
        assert result[0]["state"] == "FULL"
        assert result[0]["interface"] == "GigabitEthernet1"

    def test_routes_regex(self):
        """Regex should parse routing table"""
        parser = NTCParser()

        output = """
      2.0.0.0/32 is subnetted, 1 subnets
O        198.51.100.2 [110/2] via 10.0.12.2, 00:30:00, GigabitEthernet1
      3.0.0.0/32 is subnetted, 1 subnets
O        198.51.100.3 [110/2] via 10.0.13.2, 00:30:00, GigabitEthernet2
C        10.0.12.0 is directly connected, GigabitEthernet1
"""

        result = parser._parse_routes(output)

        assert result is not None
        assert len(result) >= 2


class TestNTCTemplateInfo:
    """Tests for template information utility"""

    def test_get_supported_platforms(self):
        """Should return list of platforms"""
        platforms = NTCTemplateInfo.get_supported_platforms()

        assert "cisco_xe" in platforms
        assert "arista_eos" in platforms
        assert "juniper" in platforms

    def test_get_platform_mapping(self):
        """Should return mapping dict"""
        mapping = NTCTemplateInfo.get_platform_mapping()

        assert isinstance(mapping, dict)
        assert mapping["cisco_xe"] == "cisco_ios"

    def test_list_templates(self):
        """Should list available templates"""
        result = NTCTemplateInfo.list_templates()

        assert "count" in result
        assert result["count"] > 0
        assert "templates" in result

    def test_list_templates_filtered(self):
        """Should filter templates by platform"""
        result = NTCTemplateInfo.list_templates(platform="cisco_ios")

        assert "count" in result
        for template in result.get("templates", []):
            assert "cisco_ios" in template["platform"]


class TestGetNTCParser:
    """Tests for singleton parser"""

    def test_returns_parser(self):
        """Should return NTCParser instance"""
        parser = get_ntc_parser()
        assert isinstance(parser, NTCParser)

    def test_returns_same_instance(self):
        """Should return same instance"""
        parser1 = get_ntc_parser()
        parser2 = get_ntc_parser()
        assert parser1 is parser2
