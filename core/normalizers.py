"""
Schema Normalization for Parser Outputs

Handles the challenge of different parsers (Genie, NTC-Templates) returning
data with different field names and structures. Provides:

1. NormalizerRegistry - Maps vendor-specific field names to canonical names
2. NormalizerValidator - Validates required fields are present after normalization

Usage:
    from core.normalizers import NormalizerRegistry, NormalizerValidator

    # Normalize parser output
    normalized = NormalizerRegistry.normalize("ospf", raw_data)

    # Validate required fields
    validation = NormalizerValidator.validate("ospf", normalized)
    if not validation.is_valid:
        logger.warning(f"Missing fields: {validation.missing_fields}")
"""

import re
import logging
from typing import Dict, Any, List, Optional, Set
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class FieldMapping:
    """Maps vendor-specific field names to canonical names"""
    canonical: str
    patterns: List[str]  # Regex patterns to match


@dataclass
class ValidationResult:
    """Result of schema validation"""
    is_valid: bool
    feature: str
    missing_fields: List[str] = field(default_factory=list)
    extra_fields: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "is_valid": self.is_valid,
            "feature": self.feature,
            "missing_fields": self.missing_fields,
            "extra_fields": self.extra_fields,
            "warnings": self.warnings,
        }


class NormalizerRegistry:
    """
    Normalizes parser outputs to consistent schema.
    Handles Genie vs NTC naming differences.
    """

    # Canonical field mappings by feature
    OSPF_FIELDS = [
        FieldMapping("neighbor_id", [r"neighbor_id", r"neighborid", r"neighbor", r"router_id"]),
        FieldMapping("state", [r"state", r"adj_state", r"adjacency_state", r"ospf_state"]),
        FieldMapping("interface", [r"interface", r"intf", r"local_interface", r"iface"]),
        FieldMapping("area", [r"area", r"area_id", r"ospf_area"]),
        FieldMapping("priority", [r"priority", r"pri", r"dr_priority"]),
        FieldMapping("dead_time", [r"dead_time", r"dead", r"dead_timer", r"dead_interval"]),
        FieldMapping("address", [r"address", r"ip_address", r"neighbor_address", r"ip"]),
    ]

    BGP_FIELDS = [
        FieldMapping("peer_address", [r"peer_address", r"neighbor", r"peer", r"remote_ip", r"neighbor_id"]),
        FieldMapping("peer_as", [r"peer_as", r"remote_as", r"asn", r"as", r"remote_asn"]),
        FieldMapping("state", [r"state", r"bgp_state", r"session_state", r"connection_state"]),
        FieldMapping("prefixes_received", [r"prefixes_received", r"rcvd", r"prefixes_rcvd", r"received_prefixes"]),
        FieldMapping("prefixes_sent", [r"prefixes_sent", r"sent", r"advertised_prefixes"]),
        FieldMapping("uptime", [r"uptime", r"up_time", r"established", r"established_time"]),
        FieldMapping("local_as", [r"local_as", r"local_asn", r"my_as"]),
    ]

    INTERFACE_FIELDS = [
        FieldMapping("name", [r"name", r"interface", r"intf", r"interface_name"]),
        FieldMapping("status", [r"status", r"oper_status", r"state", r"link_status", r"line_protocol"]),
        FieldMapping("admin_status", [r"admin_status", r"enabled", r"admin_state", r"admin"]),
        FieldMapping("mtu", [r"mtu", r"max_mtu"]),
        FieldMapping("speed", [r"speed", r"bandwidth", r"bw"]),
        FieldMapping("mac_address", [r"mac_address", r"mac", r"hardware_address", r"bia"]),
        FieldMapping("ip_address", [r"ip_address", r"ipv4_address", r"ip", r"address"]),
        FieldMapping("description", [r"description", r"desc", r"intf_description"]),
    ]

    ROUTING_FIELDS = [
        FieldMapping("destination", [r"destination", r"network", r"prefix", r"dest"]),
        FieldMapping("next_hop", [r"next_hop", r"nexthop", r"gateway", r"via"]),
        FieldMapping("protocol", [r"protocol", r"route_type", r"source_protocol", r"type"]),
        FieldMapping("metric", [r"metric", r"cost", r"distance"]),
        FieldMapping("interface", [r"interface", r"outgoing_interface", r"exit_interface"]),
        FieldMapping("preference", [r"preference", r"admin_distance", r"ad"]),
    ]

    _registries: Dict[str, List[FieldMapping]] = {
        "ospf": OSPF_FIELDS,
        "bgp": BGP_FIELDS,
        "interface": INTERFACE_FIELDS,
        "routing": ROUTING_FIELDS,
    }

    @classmethod
    def normalize(cls, feature: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Normalize parser output to canonical schema.

        Args:
            feature: Feature type (ospf, bgp, interface, routing)
            data: Raw parser output

        Returns:
            Normalized dict with consistent field names
        """
        if feature not in cls._registries:
            logger.debug(f"No normalization defined for feature: {feature}")
            return data

        mappings = cls._registries[feature]
        return cls._normalize_dict(data, mappings)

    @classmethod
    def _normalize_dict(cls, data: Any, mappings: List[FieldMapping]) -> Any:
        """Recursively normalize dict keys"""
        if isinstance(data, dict):
            result = {}
            for key, value in data.items():
                canonical_key = cls._find_canonical(key, mappings)
                result[canonical_key] = cls._normalize_dict(value, mappings)
            return result
        elif isinstance(data, list):
            return [cls._normalize_dict(item, mappings) for item in data]
        else:
            return data

    @classmethod
    def _find_canonical(cls, key: str, mappings: List[FieldMapping]) -> str:
        """Find canonical name for a field, or return original"""
        key_lower = key.lower()
        for mapping in mappings:
            for pattern in mapping.patterns:
                if re.match(f"^{pattern}$", key_lower):
                    return mapping.canonical
        return key  # No mapping found, keep original

    @classmethod
    def get_supported_features(cls) -> List[str]:
        """Get list of features with normalization support"""
        return list(cls._registries.keys())

    @classmethod
    def get_canonical_fields(cls, feature: str) -> List[str]:
        """Get list of canonical field names for a feature"""
        if feature not in cls._registries:
            return []
        return [m.canonical for m in cls._registries[feature]]


class NormalizerValidator:
    """
    Validates normalized data structures have required fields.
    Provides early warnings before consumers hit KeyError exceptions.
    """

    # Required fields per feature (must be present for valid data)
    REQUIRED_FIELDS: Dict[str, Set[str]] = {
        "ospf": {"neighbor_id", "state"},
        "bgp": {"peer_address", "peer_as", "state"},
        "interface": {"name", "status"},
        "routing": {"destination", "next_hop"},
    }

    # Optional but recommended fields
    RECOMMENDED_FIELDS: Dict[str, Set[str]] = {
        "ospf": {"interface", "area", "address"},
        "bgp": {"uptime", "prefixes_received"},
        "interface": {"admin_status", "mtu", "speed"},
        "routing": {"protocol", "metric"},
    }

    @classmethod
    def validate(
        cls,
        feature: str,
        data: Dict[str, Any],
        strict: bool = False
    ) -> ValidationResult:
        """
        Validate normalized data has required fields.

        Args:
            feature: Feature type (ospf, bgp, interface, routing)
            data: Normalized data to validate
            strict: If True, also check recommended fields

        Returns:
            ValidationResult with missing/extra field information
        """
        if feature not in cls.REQUIRED_FIELDS:
            return ValidationResult(
                is_valid=True,
                feature=feature,
                warnings=[f"No validation rules for feature: {feature}"]
            )

        required = cls.REQUIRED_FIELDS[feature]
        recommended = cls.RECOMMENDED_FIELDS.get(feature, set())

        # Handle nested data (list of items or nested dict)
        items_to_check = cls._extract_items(data)

        if not items_to_check:
            return ValidationResult(
                is_valid=False,
                feature=feature,
                missing_fields=list(required),
                warnings=["No data items found to validate"]
            )

        # Check first item for structure (assumes consistent structure)
        first_item = items_to_check[0] if items_to_check else {}
        present_fields = set(first_item.keys()) if isinstance(first_item, dict) else set()

        missing_required = required - present_fields
        missing_recommended = recommended - present_fields if strict else set()

        warnings = []
        if missing_recommended:
            warnings.append(f"Missing recommended fields: {list(missing_recommended)}")

        return ValidationResult(
            is_valid=len(missing_required) == 0,
            feature=feature,
            missing_fields=list(missing_required),
            warnings=warnings
        )

    @classmethod
    def _extract_items(cls, data: Any) -> List[Dict]:
        """Extract list of items from various data structures"""
        if isinstance(data, list):
            return [item for item in data if isinstance(item, dict)]
        elif isinstance(data, dict):
            # Check if it's a container of items
            for key, value in data.items():
                if isinstance(value, list):
                    return [item for item in value if isinstance(item, dict)]
                elif isinstance(value, dict):
                    # Could be nested structure, return as single item
                    return [value]
            # Return the dict itself as a single item
            return [data]
        return []

    @classmethod
    def validate_and_warn(
        cls,
        feature: str,
        data: Dict[str, Any],
        strict: bool = False
    ) -> Dict[str, Any]:
        """
        Validate and log warnings, but always return data.

        Useful for graceful degradation - log issues but don't block.

        Args:
            feature: Feature type
            data: Data to validate
            strict: Check recommended fields too

        Returns:
            Original data (unmodified)
        """
        result = cls.validate(feature, data, strict)

        if not result.is_valid:
            logger.warning(
                f"Validation failed for {feature}: missing {result.missing_fields}"
            )
        elif result.warnings:
            logger.info(f"Validation warnings for {feature}: {result.warnings}")

        return data
