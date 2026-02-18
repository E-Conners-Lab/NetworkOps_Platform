"""
Unified Parser - Multi-Parser Orchestration

Provides a single interface for parsing network device output using the best
available parser. Tries parsers in order of preference:

1. Genie (Cisco pyATS) - Best for Cisco devices, structured models
2. NTC-Templates (TextFSM) - Wide multi-vendor support
3. Regex fallback - Basic pattern matching
4. Raw output - Always succeeds

Feature Flags:
- use_ntc_templates: Enable NTC-Templates as fallback (default: false)
- use_normalizer: Normalize output to consistent schema (default: true)

Usage:
    from core.unified_parser import UnifiedParser

    parser = UnifiedParser()
    result = parser.parse("show ip ospf neighbor", output, platform="cisco_ios")

    if result.success:
        print(f"Parsed by: {result.parser}")
        print(result.data)
"""

import logging
import time
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
from enum import Enum

from core.feature_flags import is_enabled
from core.ntc_parser import NTCParser, ParseResult, get_ntc_parser
from core.normalizers import NormalizerRegistry, NormalizerValidator
from core.metrics import TestMetrics

logger = logging.getLogger(__name__)


class ParserType(Enum):
    """Available parser types"""
    GENIE = "genie"
    NTC = "ntc"
    REGEX = "regex"
    RAW = "raw"


@dataclass
class UnifiedParseResult:
    """Extended parse result with metadata"""
    success: bool
    parser: str
    data: Any
    normalized_data: Any  # After schema normalization
    command: str
    platform: str
    feature: Optional[str] = None  # Detected feature type
    parse_time_ms: float = 0.0
    parsers_tried: List[str] = field(default_factory=list)
    validation_warnings: List[str] = field(default_factory=list)
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "success": self.success,
            "parser": self.parser,
            "data": self.data,
            "normalized_data": self.normalized_data,
            "command": self.command,
            "platform": self.platform,
            "feature": self.feature,
            "parse_time_ms": round(self.parse_time_ms, 2),
            "parsers_tried": self.parsers_tried,
            "validation_warnings": self.validation_warnings,
            "error": self.error,
        }


# Command to feature mapping
COMMAND_FEATURE_MAP = {
    "ospf": ["show ip ospf neighbor", "show ospf neighbor"],
    "bgp": ["show ip bgp summary", "show bgp summary", "show ip bgp"],
    "interface": ["show ip interface brief", "show interface", "show interfaces"],
    "routing": ["show ip route", "show route"],
    "eigrp": ["show ip eigrp neighbor", "show eigrp neighbor"],
}


class UnifiedParser:
    """
    Orchestrates multiple parsers for structured output parsing.

    Parser priority:
    1. Genie (pyATS) - Best for Cisco, has device models
    2. NTC-Templates - TextFSM-based, wide vendor support
    3. Regex fallback - Basic patterns
    4. Raw - Always succeeds
    """

    def __init__(self):
        self._genie_available = None
        self._ntc_parser = None
        self._metrics = TestMetrics()

    @property
    def genie_available(self) -> bool:
        """Check if Genie parser is available"""
        if self._genie_available is None:
            try:
                from genie.libs.parser.utils import get_parser
                self._genie_available = True
                logger.debug("Genie parser is available")
            except ImportError:
                self._genie_available = False
                logger.debug("Genie parser not available")
        return self._genie_available

    @property
    def ntc_parser(self) -> NTCParser:
        """Get NTC parser instance"""
        if self._ntc_parser is None:
            self._ntc_parser = get_ntc_parser()
        return self._ntc_parser

    def detect_feature(self, command: str) -> Optional[str]:
        """Detect feature type from command"""
        command_lower = command.lower()
        for feature, commands in COMMAND_FEATURE_MAP.items():
            for cmd in commands:
                if cmd in command_lower:
                    return feature
        return None

    def parse(
        self,
        command: str,
        output: str,
        platform: str,
        device: Any = None,  # Optional Genie device object
        normalize: bool = True,
    ) -> UnifiedParseResult:
        """
        Parse command output using best available parser.

        Args:
            command: Command that was executed
            output: Raw command output
            platform: Device platform (e.g., "cisco_ios", "arista_eos")
            device: Optional Genie device object for context
            normalize: Whether to normalize output (default: True)

        Returns:
            UnifiedParseResult with parsed data and metadata
        """
        start_time = time.time()
        parsers_tried = []
        feature = self.detect_feature(command)

        # Try Genie first for Cisco devices
        if self._should_try_genie(platform):
            parsers_tried.append("genie")
            genie_result = self._try_genie(command, output, platform, device)
            if genie_result:
                parse_time = (time.time() - start_time) * 1000
                self._record_metric("genie", True, parse_time)

                normalized, warnings = self._normalize_if_enabled(
                    genie_result, feature, normalize
                )

                return UnifiedParseResult(
                    success=True,
                    parser="genie",
                    data=genie_result,
                    normalized_data=normalized,
                    command=command,
                    platform=platform,
                    feature=feature,
                    parse_time_ms=parse_time,
                    parsers_tried=parsers_tried,
                    validation_warnings=warnings,
                )

        # Try NTC-Templates if enabled
        if is_enabled("use_ntc_templates"):
            parsers_tried.append("ntc")
            ntc_result = self.ntc_parser.parse(command, output, platform)
            if ntc_result.success:
                parse_time = (time.time() - start_time) * 1000
                self._record_metric("ntc", True, parse_time)

                normalized, warnings = self._normalize_if_enabled(
                    ntc_result.data, feature, normalize
                )

                return UnifiedParseResult(
                    success=True,
                    parser="ntc",
                    data=ntc_result.data,
                    normalized_data=normalized,
                    command=command,
                    platform=platform,
                    feature=feature,
                    parse_time_ms=parse_time,
                    parsers_tried=parsers_tried,
                    validation_warnings=warnings,
                )

        # Try regex fallback
        parsers_tried.append("regex")
        regex_result = self._try_regex(command, output, platform)
        if regex_result:
            parse_time = (time.time() - start_time) * 1000
            self._record_metric("regex", True, parse_time)

            normalized, warnings = self._normalize_if_enabled(
                regex_result, feature, normalize
            )

            return UnifiedParseResult(
                success=True,
                parser="regex",
                data=regex_result,
                normalized_data=normalized,
                command=command,
                platform=platform,
                feature=feature,
                parse_time_ms=parse_time,
                parsers_tried=parsers_tried,
                validation_warnings=warnings,
            )

        # Return raw output
        parse_time = (time.time() - start_time) * 1000
        self._record_metric("raw", True, parse_time)

        return UnifiedParseResult(
            success=True,
            parser="raw",
            data={"raw_output": output, "lines": output.strip().split("\n")},
            normalized_data=None,
            command=command,
            platform=platform,
            feature=feature,
            parse_time_ms=parse_time,
            parsers_tried=parsers_tried,
            validation_warnings=["No structured parser available, returning raw output"],
        )

    def _should_try_genie(self, platform: str) -> bool:
        """Determine if Genie should be tried for this platform"""
        if not self.genie_available:
            return False

        # Genie works best for Cisco platforms
        cisco_platforms = ["cisco_ios", "cisco_xe", "cisco_nxos", "cisco_xr", "cisco_asa"]
        return platform.lower() in cisco_platforms

    def _try_genie(
        self,
        command: str,
        output: str,
        platform: str,
        device: Any = None
    ) -> Optional[Dict]:
        """Try parsing with Genie"""
        try:
            from genie.libs.parser.utils import get_parser
            from genie.metaparser.util.exceptions import SchemaEmptyParserError

            # Map platform to Genie OS
            os_map = {
                "cisco_ios": "ios",
                "cisco_xe": "iosxe",
                "cisco_nxos": "nxos",
                "cisco_xr": "iosxr",
                "cisco_asa": "asa",
            }
            genie_os = os_map.get(platform.lower(), "iosxe")

            # Get parser class
            parser_class = get_parser(command, genie_os)
            if parser_class is None:
                logger.debug(f"No Genie parser for: {command}")
                return None

            # Create mock device if needed
            if device is None:
                from unittest.mock import Mock
                device = Mock()
                device.os = genie_os

            # Parse output
            parser = parser_class(device=device)
            parsed = parser.cli(output=output)

            return parsed

        except SchemaEmptyParserError:
            logger.debug(f"Genie empty result for: {command}")
            return None
        except Exception as e:
            logger.debug(f"Genie parse failed: {e}")
            return None

    def _try_regex(
        self,
        command: str,
        output: str,
        platform: str
    ) -> Optional[List[Dict]]:
        """Try regex-based parsing"""
        # Use NTC parser's regex fallback
        return self.ntc_parser._regex_fallback(command, output, platform)

    def _normalize_if_enabled(
        self,
        data: Any,
        feature: Optional[str],
        normalize: bool
    ) -> tuple:
        """Normalize data if feature flag enabled"""
        warnings = []

        if not normalize or not is_enabled("use_normalizer"):
            return data, warnings

        if feature is None:
            return data, warnings

        try:
            normalized = NormalizerRegistry.normalize(feature, data)

            # Validate normalized data
            validation = NormalizerValidator.validate(feature, normalized)
            if not validation.is_valid:
                warnings.append(f"Missing fields: {validation.missing_fields}")
            warnings.extend(validation.warnings)

            return normalized, warnings

        except Exception as e:
            logger.warning(f"Normalization failed: {e}")
            return data, [f"Normalization error: {str(e)}"]

    def _record_metric(self, parser: str, success: bool, duration_ms: float):
        """Record parsing metrics"""
        try:
            self._metrics.record_success(
                f"parser.{parser}",
                success,
                duration_ms
            )
        except Exception as e:
            logger.debug(f"Metric recording failed: {e}")

    def get_parser_stats(self) -> Dict[str, Any]:
        """Get parser usage statistics"""
        return {
            "genie_available": self.genie_available,
            "ntc_available": self.ntc_parser.is_available,
            "ntc_enabled": is_enabled("use_ntc_templates"),
            "normalizer_enabled": is_enabled("use_normalizer"),
        }


# Convenience functions
_unified_parser = None

def get_unified_parser() -> UnifiedParser:
    """Get singleton unified parser instance"""
    global _unified_parser
    if _unified_parser is None:
        _unified_parser = UnifiedParser()
    return _unified_parser


def parse_output(
    command: str,
    output: str,
    platform: str,
    normalize: bool = True
) -> UnifiedParseResult:
    """
    Convenience function to parse output.

    Args:
        command: Command that was executed
        output: Raw output
        platform: Device platform
        normalize: Whether to normalize (default: True)

    Returns:
        UnifiedParseResult
    """
    parser = get_unified_parser()
    return parser.parse(command, output, platform, normalize=normalize)
