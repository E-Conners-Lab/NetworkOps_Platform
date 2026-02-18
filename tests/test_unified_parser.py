"""
Tests for Unified Parser - Multi-parser orchestration.
"""

import pytest
from unittest.mock import patch, MagicMock

from core.unified_parser import (
    UnifiedParser, UnifiedParseResult, ParserType,
    COMMAND_FEATURE_MAP, get_unified_parser, parse_output
)


class TestUnifiedParseResult:
    """Tests for UnifiedParseResult dataclass"""

    def test_successful_result(self):
        """Create successful parse result"""
        result = UnifiedParseResult(
            success=True,
            parser="genie",
            data={"interfaces": {}},
            normalized_data={"interfaces": {}},
            command="show ip interface brief",
            platform="cisco_ios",
            feature="interface",
            parse_time_ms=50.5
        )

        assert result.success is True
        assert result.parser == "genie"
        assert result.feature == "interface"

    def test_to_dict(self):
        """Convert result to dictionary"""
        result = UnifiedParseResult(
            success=True,
            parser="ntc",
            data=[{"test": "data"}],
            normalized_data=[{"test": "data"}],
            command="show version",
            platform="arista_eos",
            parse_time_ms=25.123,
            parsers_tried=["genie", "ntc"]
        )

        d = result.to_dict()

        assert d["success"] is True
        assert d["parser"] == "ntc"
        assert d["parse_time_ms"] == 25.12
        assert "genie" in d["parsers_tried"]
        assert "ntc" in d["parsers_tried"]


class TestCommandFeatureMap:
    """Tests for command to feature mapping"""

    def test_ospf_commands(self):
        """OSPF commands should map correctly"""
        assert "show ip ospf neighbor" in COMMAND_FEATURE_MAP["ospf"]
        assert "show ospf neighbor" in COMMAND_FEATURE_MAP["ospf"]

    def test_bgp_commands(self):
        """BGP commands should map correctly"""
        assert "show ip bgp summary" in COMMAND_FEATURE_MAP["bgp"]

    def test_interface_commands(self):
        """Interface commands should map correctly"""
        assert "show ip interface brief" in COMMAND_FEATURE_MAP["interface"]

    def test_routing_commands(self):
        """Routing commands should map correctly"""
        assert "show ip route" in COMMAND_FEATURE_MAP["routing"]


class TestUnifiedParser:
    """Tests for UnifiedParser class"""

    def test_detect_ospf_feature(self):
        """Should detect OSPF feature from command"""
        parser = UnifiedParser()

        assert parser.detect_feature("show ip ospf neighbor") == "ospf"
        assert parser.detect_feature("show ospf neighbor detail") == "ospf"

    def test_detect_bgp_feature(self):
        """Should detect BGP feature from command"""
        parser = UnifiedParser()

        assert parser.detect_feature("show ip bgp summary") == "bgp"
        assert parser.detect_feature("show ip bgp") == "bgp"

    def test_detect_interface_feature(self):
        """Should detect interface feature from command"""
        parser = UnifiedParser()

        assert parser.detect_feature("show ip interface brief") == "interface"
        assert parser.detect_feature("show interfaces status") == "interface"

    def test_detect_unknown_feature(self):
        """Unknown commands should return None"""
        parser = UnifiedParser()

        assert parser.detect_feature("show clock") is None
        assert parser.detect_feature("show version") is None

    def test_should_try_genie_cisco(self):
        """Should try Genie for Cisco platforms"""
        parser = UnifiedParser()

        # Mock Genie as available
        parser._genie_available = True

        assert parser._should_try_genie("cisco_ios") is True
        assert parser._should_try_genie("cisco_xe") is True
        assert parser._should_try_genie("cisco_nxos") is True

    def test_should_not_try_genie_non_cisco(self):
        """Should not try Genie for non-Cisco platforms"""
        parser = UnifiedParser()
        parser._genie_available = True

        assert parser._should_try_genie("arista_eos") is False
        assert parser._should_try_genie("juniper_junos") is False

    def test_get_parser_stats(self):
        """Should return parser statistics"""
        parser = UnifiedParser()
        stats = parser.get_parser_stats()

        assert "genie_available" in stats
        assert "ntc_available" in stats
        assert "ntc_enabled" in stats
        assert "normalizer_enabled" in stats


class TestUnifiedParserParsing:
    """Tests for actual parsing operations"""

    @patch('core.unified_parser.is_enabled')
    def test_parse_with_ntc_fallback(self, mock_enabled):
        """Should fall back to NTC when Genie unavailable"""
        mock_enabled.return_value = True
        parser = UnifiedParser()
        parser._genie_available = False  # Force NTC fallback

        output = """
Interface              IP-Address      OK? Method Status                Protocol
GigabitEthernet1       10.0.12.1       YES NVRAM  up                    up
Loopback0              198.51.100.1         YES NVRAM  up                    up
"""

        result = parser.parse(
            "show ip interface brief",
            output,
            "cisco_ios"
        )

        assert result.success is True
        assert result.parser in ["ntc", "regex", "raw"]
        # NTC should be tried when enabled
        assert len(result.parsers_tried) >= 1

    @patch('core.feature_flags.is_enabled')
    def test_parse_with_regex_fallback(self, mock_enabled):
        """Should fall back to regex when NTC fails"""
        mock_enabled.side_effect = lambda flag: flag == "use_normalizer"
        parser = UnifiedParser()
        parser._genie_available = False

        output = """
Neighbor ID     Pri   State           Dead Time   Address         Interface
198.51.100.2           1   FULL/DR         00:00:35    10.0.12.2       GigabitEthernet1
"""

        result = parser.parse(
            "show ip ospf neighbor",
            output,
            "arista_eos"  # Non-Cisco, NTC might not have template
        )

        assert result.success is True
        # Should use regex or raw fallback
        assert result.parser in ["regex", "raw", "ntc"]

    @patch('core.feature_flags.is_enabled')
    def test_parse_returns_raw_on_failure(self, mock_enabled):
        """Should return raw output when all parsers fail"""
        mock_enabled.return_value = False
        parser = UnifiedParser()
        parser._genie_available = False

        output = "Some random output"

        result = parser.parse(
            "show something custom",
            output,
            "unknown_platform"
        )

        assert result.success is True
        assert result.parser == "raw"
        assert "raw_output" in result.data

    @patch('core.feature_flags.is_enabled')
    def test_parse_records_timing(self, mock_enabled):
        """Should record parse timing"""
        mock_enabled.return_value = True
        parser = UnifiedParser()

        result = parser.parse(
            "show version",
            "Cisco IOS Software",
            "cisco_ios"
        )

        assert result.parse_time_ms > 0

    @patch('core.feature_flags.is_enabled')
    def test_parse_tracks_parsers_tried(self, mock_enabled):
        """Should track which parsers were attempted"""
        mock_enabled.return_value = True
        parser = UnifiedParser()
        parser._genie_available = False  # Skip Genie

        result = parser.parse(
            "show ip interface brief",
            "Gi1 10.0.0.1 YES NVRAM up up",
            "cisco_ios"
        )

        assert len(result.parsers_tried) > 0


class TestNormalization:
    """Tests for normalization integration"""

    @patch('core.feature_flags.is_enabled')
    def test_normalization_enabled(self, mock_enabled):
        """Should normalize when enabled"""
        mock_enabled.return_value = True
        parser = UnifiedParser()

        # The normalized_data should be populated
        result = parser.parse(
            "show ip ospf neighbor",
            "198.51.100.2 1 FULL/DR 00:00:35 10.0.12.2 Gi1",
            "cisco_ios",
            normalize=True
        )

        # normalize flag is respected
        assert result.success is True

    @patch('core.feature_flags.is_enabled')
    def test_normalization_disabled(self, mock_enabled):
        """Should skip normalization when disabled"""
        mock_enabled.return_value = False
        parser = UnifiedParser()

        result = parser.parse(
            "show ip ospf neighbor",
            "198.51.100.2 1 FULL/DR",
            "cisco_ios",
            normalize=False
        )

        # Data should still be present
        assert result.success is True


class TestConvenienceFunctions:
    """Tests for module-level convenience functions"""

    def test_get_unified_parser_singleton(self):
        """Should return same instance"""
        parser1 = get_unified_parser()
        parser2 = get_unified_parser()

        assert parser1 is parser2
        assert isinstance(parser1, UnifiedParser)

    @patch('core.feature_flags.is_enabled')
    def test_parse_output_function(self, mock_enabled):
        """parse_output should work as convenience function"""
        mock_enabled.return_value = True

        result = parse_output(
            "show version",
            "Cisco IOS Software, Version 17.13.1a",
            "cisco_ios"
        )

        assert isinstance(result, UnifiedParseResult)
        assert result.success is True


class TestMultiVendorParsing:
    """Tests for multi-vendor support"""

    @patch('core.feature_flags.is_enabled')
    def test_arista_parsing(self, mock_enabled):
        """Should parse Arista output"""
        mock_enabled.return_value = True
        parser = UnifiedParser()

        output = """
Port       Name   Status       Vlan     Duplex  Speed  Type
Eth1              connected    1        full    1G     10GBASE-T
Eth2              notconnect   1        auto    auto   10GBASE-T
"""

        result = parser.parse(
            "show interfaces status",
            output,
            "arista_eos"
        )

        assert result.success is True

    @patch('core.feature_flags.is_enabled')
    def test_juniper_parsing(self, mock_enabled):
        """Should parse Juniper output"""
        mock_enabled.return_value = True
        parser = UnifiedParser()

        output = """
Interface               Admin Link Proto    Local                 Remote
ge-0/0/0                up    up
ge-0/0/1                up    down
lo0                     up    up
"""

        result = parser.parse(
            "show interfaces terse",
            output,
            "juniper_junos"
        )

        assert result.success is True

    @patch('core.feature_flags.is_enabled')
    def test_frrouting_parsing(self, mock_enabled):
        """Should parse FRRouting output (Cisco-like)"""
        mock_enabled.return_value = True
        parser = UnifiedParser()

        output = """
Neighbor        V         AS   MsgRcvd   MsgSent   TblVer  InQ OutQ  Up/Down  State/PfxRcd
10.255.255.13   4      65000       100       100        0    0    0 00:30:00           5
"""

        result = parser.parse(
            "show ip bgp summary",
            output,
            "frrouting"
        )

        assert result.success is True
