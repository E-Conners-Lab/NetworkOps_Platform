"""
NTC-Templates Parser Integration

Provides structured parsing for multi-vendor network device output using
NTC-Templates (TextFSM-based parsing). Supports vendors that Genie doesn't
cover: Arista, Juniper, Palo Alto, Fortinet, HPE, and more.

Feature Flag: use_ntc_templates (default: false)

Usage:
    from core.ntc_parser import NTCParser

    parser = NTCParser()
    result = parser.parse("show ip route", output, platform="arista_eos")
"""

import logging
import re
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, field

from core.feature_flags import is_enabled

logger = logging.getLogger(__name__)


@dataclass
class ParseResult:
    """Result of parsing operation"""
    success: bool
    parser: str  # "ntc", "genie", "regex", "raw"
    data: Any
    command: str
    platform: str
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "success": self.success,
            "parser": self.parser,
            "data": self.data,
            "command": self.command,
            "platform": self.platform,
            "error": self.error,
        }


# Platform mapping: our device types to NTC-Templates platforms
PLATFORM_MAP = {
    # Cisco
    "cisco_xe": "cisco_ios",
    "cisco_ios": "cisco_ios",
    "cisco_nxos": "cisco_nxos",
    "cisco_asa": "cisco_asa",
    "cisco_xr": "cisco_xr",
    # Arista
    "arista_eos": "arista_eos",
    "arista": "arista_eos",
    # Juniper
    "juniper_junos": "juniper_junos",
    "juniper": "juniper_junos",
    # Palo Alto
    "paloalto": "paloalto_panos",
    "paloalto_panos": "paloalto_panos",
    # Fortinet
    "fortinet": "fortinet_fortios",
    "fortinet_fortios": "fortinet_fortios",
    # HPE/Aruba
    "hp_procurve": "hp_procurve",
    "hp_comware": "hp_comware",
    "aruba_os": "aruba_os",
    # Linux
    "linux": "linux",
    # FRRouting (uses Quagga templates)
    "frrouting": "cisco_ios",  # FRR output is Cisco-like
    "frr": "cisco_ios",
    # Nokia
    "nokia_sros": "nokia_sros",
    "nokia_srlinux": "nokia_srlinux",
}

# Common commands supported across platforms
SUPPORTED_COMMANDS = {
    "cisco_ios": [
        "show ip interface brief",
        "show interfaces",
        "show ip route",
        "show ip ospf neighbor",
        "show ip bgp summary",
        "show ip bgp",
        "show cdp neighbors",
        "show cdp neighbors detail",
        "show lldp neighbors",
        "show version",
        "show inventory",
        "show ip arp",
        "show mac address-table",
        "show vlan",
        "show spanning-tree",
        "show ip eigrp neighbors",
        "show ntp status",
        "show clock",
    ],
    "arista_eos": [
        "show ip interface brief",
        "show interfaces status",
        "show ip route",
        "show ip ospf neighbor",
        "show ip bgp summary",
        "show lldp neighbors",
        "show version",
        "show inventory",
        "show ip arp",
        "show mac address-table",
        "show vlan",
    ],
    "juniper_junos": [
        "show interfaces terse",
        "show route",
        "show ospf neighbor",
        "show bgp summary",
        "show lldp neighbors",
        "show version",
        "show chassis hardware",
        "show arp",
    ],
}


class NTCParser:
    """
    Parser using NTC-Templates (TextFSM) for structured output parsing.

    Provides multi-vendor support for devices not covered by Cisco Genie.
    """

    def __init__(self):
        self._ntc_available = None
        self._templates_loaded = False

    @property
    def is_available(self) -> bool:
        """Check if ntc-templates is installed and usable"""
        if self._ntc_available is None:
            try:
                import ntc_templates
                from ntc_templates import parse
                self._ntc_available = True
                logger.debug("ntc-templates is available")
            except ImportError:
                self._ntc_available = False
                logger.warning("ntc-templates not installed. Install with: pip install ntc-templates")
        return self._ntc_available

    def get_platform(self, device_type: str) -> str:
        """Map device type to NTC-Templates platform"""
        return PLATFORM_MAP.get(device_type.lower(), device_type)

    def get_supported_commands(self, platform: str) -> List[str]:
        """Get list of commands with templates for a platform"""
        ntc_platform = self.get_platform(platform)
        return SUPPORTED_COMMANDS.get(ntc_platform, [])

    def parse(
        self,
        command: str,
        output: str,
        platform: str,
    ) -> ParseResult:
        """
        Parse command output using NTC-Templates.

        Args:
            command: The command that was executed
            output: Raw command output
            platform: Device platform (e.g., "arista_eos", "cisco_ios")

        Returns:
            ParseResult with structured data or error
        """
        if not is_enabled("use_ntc_templates"):
            return ParseResult(
                success=False,
                parser="ntc",
                data=None,
                command=command,
                platform=platform,
                error="NTC-Templates disabled (use_ntc_templates=false)"
            )

        if not self.is_available:
            return ParseResult(
                success=False,
                parser="ntc",
                data=None,
                command=command,
                platform=platform,
                error="ntc-templates not installed"
            )

        try:
            from ntc_templates import parse

            ntc_platform = self.get_platform(platform)

            # Parse using ntc-templates
            parsed = parse.parse_output(
                platform=ntc_platform,
                command=command,
                data=output
            )

            if parsed:
                logger.debug(f"NTC parsed {command} for {platform}: {len(parsed)} entries")
                return ParseResult(
                    success=True,
                    parser="ntc",
                    data=parsed,
                    command=command,
                    platform=platform
                )
            else:
                return ParseResult(
                    success=False,
                    parser="ntc",
                    data=None,
                    command=command,
                    platform=platform,
                    error="No template match or empty output"
                )

        except Exception as e:
            logger.warning(f"NTC parse failed for {command}: {e}")
            return ParseResult(
                success=False,
                parser="ntc",
                data=None,
                command=command,
                platform=platform,
                error=str(e)
            )

    def parse_with_fallback(
        self,
        command: str,
        output: str,
        platform: str,
    ) -> ParseResult:
        """
        Parse with regex fallback if NTC fails.

        Args:
            command: Command executed
            output: Raw output
            platform: Device platform

        Returns:
            ParseResult from NTC or regex fallback
        """
        # Try NTC first
        result = self.parse(command, output, platform)
        if result.success:
            return result

        # Try regex fallback for common commands
        fallback = self._regex_fallback(command, output, platform)
        if fallback:
            return ParseResult(
                success=True,
                parser="regex",
                data=fallback,
                command=command,
                platform=platform
            )

        # Return raw output
        return ParseResult(
            success=True,
            parser="raw",
            data={"raw_output": output},
            command=command,
            platform=platform
        )

    def _regex_fallback(
        self,
        command: str,
        output: str,
        platform: str
    ) -> Optional[List[Dict]]:
        """Regex-based fallback parsing for common patterns"""

        command_lower = command.lower()

        # IP interface brief pattern
        if "interface" in command_lower and "brief" in command_lower:
            return self._parse_interface_brief(output)

        # BGP summary pattern
        if "bgp" in command_lower and "summary" in command_lower:
            return self._parse_bgp_summary(output)

        # OSPF neighbor pattern
        if "ospf" in command_lower and "neighbor" in command_lower:
            return self._parse_ospf_neighbors(output)

        # Route/routing table
        if "route" in command_lower and "ip" in command_lower:
            return self._parse_routes(output)

        return None

    def _parse_interface_brief(self, output: str) -> List[Dict]:
        """Parse show ip interface brief output"""
        results = []
        # Pattern: Interface  IP-Address  OK? Method Status  Protocol
        pattern = r"(\S+)\s+(\d+\.\d+\.\d+\.\d+|unassigned)\s+\S+\s+\S+\s+(\S+)\s+(\S+)"

        for match in re.finditer(pattern, output):
            results.append({
                "interface": match.group(1),
                "ip_address": match.group(2),
                "status": match.group(3),
                "protocol": match.group(4),
            })

        return results if results else None

    def _parse_bgp_summary(self, output: str) -> List[Dict]:
        """Parse BGP summary output"""
        results = []
        # Pattern: Neighbor  V  AS  MsgRcvd MsgSent TblVer InQ OutQ Up/Down State/PfxRcd
        pattern = r"(\d+\.\d+\.\d+\.\d+)\s+\d+\s+(\d+)\s+\d+\s+\d+\s+\d+\s+\d+\s+\d+\s+(\S+)\s+(\S+)"

        for match in re.finditer(pattern, output):
            state_or_pfx = match.group(4)
            results.append({
                "neighbor": match.group(1),
                "remote_as": int(match.group(2)),
                "up_down": match.group(3),
                "state_pfxrcd": state_or_pfx,
                "state": "Established" if state_or_pfx.isdigit() else state_or_pfx,
            })

        return results if results else None

    def _parse_ospf_neighbors(self, output: str) -> List[Dict]:
        """Parse OSPF neighbor output"""
        results = []
        # Pattern: Neighbor ID Pri State Dead Time Address Interface
        pattern = r"(\d+\.\d+\.\d+\.\d+)\s+(\d+)\s+(FULL|2WAY|INIT|DOWN)[/\w]*\s+(\S+)\s+(\d+\.\d+\.\d+\.\d+)\s+(\S+)"

        for match in re.finditer(pattern, output, re.IGNORECASE):
            results.append({
                "neighbor_id": match.group(1),
                "priority": int(match.group(2)),
                "state": match.group(3),
                "dead_time": match.group(4),
                "address": match.group(5),
                "interface": match.group(6),
            })

        return results if results else None

    def _parse_routes(self, output: str) -> List[Dict]:
        """Parse routing table output"""
        results = []
        # Pattern for Cisco-style: C/O/S/B prefix [AD/metric] via next-hop
        pattern = r"([COSBDRE\*])\s+(\d+\.\d+\.\d+\.\d+/?\d*)\s+(?:\[(\d+)/(\d+)\])?\s*(?:via\s+)?(\d+\.\d+\.\d+\.\d+)?"

        for match in re.finditer(pattern, output):
            protocol_map = {
                "C": "connected",
                "O": "ospf",
                "S": "static",
                "B": "bgp",
                "D": "eigrp",
                "R": "rip",
                "E": "eigrp",
            }
            results.append({
                "protocol": protocol_map.get(match.group(1), match.group(1)),
                "network": match.group(2),
                "admin_distance": int(match.group(3)) if match.group(3) else None,
                "metric": int(match.group(4)) if match.group(4) else None,
                "next_hop": match.group(5),
            })

        return results if results else None


class NTCTemplateInfo:
    """Utility to get information about available NTC templates"""

    @staticmethod
    def get_supported_platforms() -> List[str]:
        """Get list of platforms with NTC template support"""
        return list(PLATFORM_MAP.keys())

    @staticmethod
    def get_platform_mapping() -> Dict[str, str]:
        """Get mapping from our device types to NTC platforms"""
        return PLATFORM_MAP.copy()

    @staticmethod
    def list_templates(platform: str = None) -> Dict[str, Any]:
        """
        List available templates.

        Args:
            platform: Filter by platform (optional)

        Returns:
            Dict with template information
        """
        try:
            import ntc_templates
            import os

            template_dir = os.path.join(
                os.path.dirname(ntc_templates.__file__),
                "templates"
            )

            templates = []
            for f in os.listdir(template_dir):
                if f.endswith(".textfsm"):
                    parts = f.replace(".textfsm", "").split("_", 2)
                    if len(parts) >= 3:
                        vendor = parts[0]
                        os_type = parts[1]
                        command = parts[2].replace("_", " ")
                        plat = f"{vendor}_{os_type}"

                        if platform is None or platform in plat:
                            templates.append({
                                "platform": plat,
                                "command": command,
                                "file": f
                            })

            return {
                "count": len(templates),
                "templates": templates
            }

        except ImportError:
            return {"error": "ntc-templates not installed"}
        except Exception as e:
            return {"error": str(e)}


# Singleton instance
_parser = None

def get_ntc_parser() -> NTCParser:
    """Get singleton NTC parser instance"""
    global _parser
    if _parser is None:
        _parser = NTCParser()
    return _parser
