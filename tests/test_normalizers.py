"""
Tests for schema normalization and validation.
"""

import pytest
from core.normalizers import NormalizerRegistry, NormalizerValidator, ValidationResult


class TestNormalizerRegistry:
    """Tests for field name normalization"""

    def test_normalize_ospf_fields(self):
        """Test OSPF field normalization"""
        raw_data = {
            "neighborid": "198.51.100.2",
            "adj_state": "FULL",
            "intf": "GigabitEthernet1",
            "area_id": "0.0.0.0"
        }

        normalized = NormalizerRegistry.normalize("ospf", raw_data)

        assert normalized["neighbor_id"] == "198.51.100.2"
        assert normalized["state"] == "FULL"
        assert normalized["interface"] == "GigabitEthernet1"
        assert normalized["area"] == "0.0.0.0"

    def test_normalize_bgp_fields(self):
        """Test BGP field normalization"""
        raw_data = {
            "neighbor": "10.0.0.1",
            "remote_as": 65001,
            "session_state": "Established",
            "rcvd": 150
        }

        normalized = NormalizerRegistry.normalize("bgp", raw_data)

        assert normalized["peer_address"] == "10.0.0.1"
        assert normalized["peer_as"] == 65001
        assert normalized["state"] == "Established"
        assert normalized["prefixes_received"] == 150

    def test_normalize_interface_fields(self):
        """Test interface field normalization"""
        raw_data = {
            "interface_name": "Gi1",
            "oper_status": "up",
            "admin": "enabled",
            "bw": 1000000
        }

        normalized = NormalizerRegistry.normalize("interface", raw_data)

        assert normalized["name"] == "Gi1"
        assert normalized["status"] == "up"
        assert normalized["admin_status"] == "enabled"
        assert normalized["speed"] == 1000000

    def test_normalize_nested_data(self):
        """Test normalization of nested dictionaries"""
        raw_data = {
            "vrf": {
                "default": {
                    "neighbors": {
                        "198.51.100.2": {
                            "neighborid": "198.51.100.2",
                            "adj_state": "FULL"
                        }
                    }
                }
            }
        }

        normalized = NormalizerRegistry.normalize("ospf", raw_data)

        assert "vrf" in normalized
        assert normalized["vrf"]["default"]["neighbors"]["198.51.100.2"]["neighbor_id"] == "198.51.100.2"
        assert normalized["vrf"]["default"]["neighbors"]["198.51.100.2"]["state"] == "FULL"

    def test_normalize_list_data(self):
        """Test normalization of lists"""
        raw_data = {
            "neighbors": [
                {"neighborid": "198.51.100.2", "adj_state": "FULL"},
                {"neighborid": "198.51.100.3", "adj_state": "FULL"}
            ]
        }

        normalized = NormalizerRegistry.normalize("ospf", raw_data)

        assert len(normalized["neighbors"]) == 2
        assert normalized["neighbors"][0]["neighbor_id"] == "198.51.100.2"
        assert normalized["neighbors"][1]["neighbor_id"] == "198.51.100.3"

    def test_unknown_fields_preserved(self):
        """Unknown fields should be preserved unchanged"""
        raw_data = {
            "neighborid": "198.51.100.2",
            "custom_field": "custom_value"
        }

        normalized = NormalizerRegistry.normalize("ospf", raw_data)

        assert normalized["neighbor_id"] == "198.51.100.2"
        assert normalized["custom_field"] == "custom_value"

    def test_unknown_feature_returns_unchanged(self):
        """Unknown feature should return data unchanged"""
        raw_data = {"key": "value"}
        normalized = NormalizerRegistry.normalize("unknown_feature", raw_data)

        assert normalized == raw_data

    def test_get_supported_features(self):
        """Test getting list of supported features"""
        features = NormalizerRegistry.get_supported_features()

        assert "ospf" in features
        assert "bgp" in features
        assert "interface" in features
        assert "routing" in features

    def test_get_canonical_fields(self):
        """Test getting canonical field names for a feature"""
        fields = NormalizerRegistry.get_canonical_fields("ospf")

        assert "neighbor_id" in fields
        assert "state" in fields
        assert "interface" in fields


class TestNormalizerValidator:
    """Tests for schema validation"""

    def test_valid_ospf_data(self):
        """Valid OSPF data should pass validation"""
        data = {
            "neighbors": [
                {"neighbor_id": "198.51.100.2", "state": "FULL", "interface": "Gi1"}
            ]
        }

        result = NormalizerValidator.validate("ospf", data)

        assert result.is_valid is True
        assert len(result.missing_fields) == 0

    def test_invalid_ospf_missing_required(self):
        """Missing required fields should fail validation"""
        data = {
            "neighbors": [
                {"interface": "Gi1"}  # Missing neighbor_id and state
            ]
        }

        result = NormalizerValidator.validate("ospf", data)

        assert result.is_valid is False
        assert "neighbor_id" in result.missing_fields
        assert "state" in result.missing_fields

    def test_valid_bgp_data(self):
        """Valid BGP data should pass validation"""
        data = [
            {"peer_address": "10.0.0.1", "peer_as": 65001, "state": "Established"}
        ]

        result = NormalizerValidator.validate("bgp", data)

        assert result.is_valid is True

    def test_strict_mode_checks_recommended(self):
        """Strict mode should warn about missing recommended fields"""
        data = [
            {"neighbor_id": "198.51.100.2", "state": "FULL"}
            # Missing recommended: interface, area
        ]

        result = NormalizerValidator.validate("ospf", data, strict=True)

        assert result.is_valid is True  # Still valid, just has warnings
        assert len(result.warnings) > 0

    def test_unknown_feature_passes(self):
        """Unknown feature should pass with warning"""
        data = {"key": "value"}
        result = NormalizerValidator.validate("unknown_feature", data)

        assert result.is_valid is True
        assert len(result.warnings) > 0

    def test_empty_data_fails(self):
        """Empty data should fail validation due to missing required fields"""
        result = NormalizerValidator.validate("ospf", {})

        assert result.is_valid is False
        # Empty dict has no required fields
        assert "neighbor_id" in result.missing_fields
        assert "state" in result.missing_fields

    def test_validate_and_warn_returns_data(self):
        """validate_and_warn should return original data"""
        data = {"neighbor_id": "198.51.100.2", "state": "FULL"}

        returned = NormalizerValidator.validate_and_warn("ospf", data)

        assert returned == data

    def test_validation_result_to_dict(self):
        """ValidationResult.to_dict should return proper structure"""
        result = ValidationResult(
            is_valid=False,
            feature="ospf",
            missing_fields=["neighbor_id"],
            warnings=["Test warning"]
        )

        result_dict = result.to_dict()

        assert result_dict["is_valid"] is False
        assert result_dict["feature"] == "ospf"
        assert "neighbor_id" in result_dict["missing_fields"]
        assert "Test warning" in result_dict["warnings"]


class TestNormalizerIntegration:
    """Integration tests for normalization + validation"""

    def test_normalize_then_validate(self):
        """Data should pass validation after normalization"""
        # Raw data with vendor-specific field names
        raw_data = {
            "neighbors": [
                {"neighborid": "198.51.100.2", "adj_state": "FULL"}
            ]
        }

        # Normalize
        normalized = NormalizerRegistry.normalize("ospf", raw_data)

        # Validate
        result = NormalizerValidator.validate("ospf", normalized)

        assert result.is_valid is True
        assert len(result.missing_fields) == 0
