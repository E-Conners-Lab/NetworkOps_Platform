"""
Tests for input validation and sanitization in network_ops.

Security coverage:
- IP address validation (IPv4/IPv6)
- Hostname validation (RFC 1123)
- Ping count validation (range 1-10)
- Shell injection prevention (metacharacter rejection)

Run with: pytest tests/test_input_validation.py -v
"""

import pytest
import sys
import os

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dashboard.routes.network_ops import validate_ip_or_hostname, validate_ping_count


class TestValidateIpOrHostname:
    """Tests for IP address and hostname validation."""

    # ==========================================================================
    # Valid IPv4 addresses
    # ==========================================================================

    def test_valid_ipv4_loopback(self):
        """Loopback address should be valid."""
        is_valid, error = validate_ip_or_hostname("127.0.0.1")
        assert is_valid is True
        assert error == ""

    def test_valid_ipv4_private(self):
        """Private network addresses should be valid."""
        is_valid, error = validate_ip_or_hostname("10.255.255.11")
        assert is_valid is True
        assert error == ""

    def test_valid_ipv4_public(self):
        """Public addresses should be valid."""
        is_valid, error = validate_ip_or_hostname("8.8.8.8")
        assert is_valid is True
        assert error == ""

    def test_valid_ipv4_broadcast(self):
        """Broadcast address should be valid."""
        is_valid, error = validate_ip_or_hostname("255.255.255.255")
        assert is_valid is True
        assert error == ""

    # ==========================================================================
    # Valid IPv6 addresses
    # ==========================================================================

    def test_valid_ipv6_loopback(self):
        """IPv6 loopback should be valid."""
        is_valid, error = validate_ip_or_hostname("::1")
        assert is_valid is True
        assert error == ""

    def test_valid_ipv6_full(self):
        """Full IPv6 address should be valid."""
        is_valid, error = validate_ip_or_hostname("2001:0db8:85a3:0000:0000:8a2e:0370:7334")
        assert is_valid is True
        assert error == ""

    def test_valid_ipv6_compressed(self):
        """Compressed IPv6 address should be valid."""
        is_valid, error = validate_ip_or_hostname("2001:db8::1")
        assert is_valid is True
        assert error == ""

    # ==========================================================================
    # Valid hostnames
    # ==========================================================================

    def test_valid_hostname_simple(self):
        """Simple hostname should be valid."""
        is_valid, error = validate_ip_or_hostname("router1")
        assert is_valid is True
        assert error == ""

    def test_valid_hostname_with_hyphen(self):
        """Hostname with hyphen should be valid."""
        is_valid, error = validate_ip_or_hostname("switch-r1")
        assert is_valid is True
        assert error == ""

    def test_valid_hostname_fqdn(self):
        """Fully qualified domain name should be valid."""
        is_valid, error = validate_ip_or_hostname("router1.lab.example.com")
        assert is_valid is True
        assert error == ""

    def test_valid_hostname_with_numbers(self):
        """Hostname with numbers should be valid."""
        is_valid, error = validate_ip_or_hostname("r2d2")
        assert is_valid is True
        assert error == ""

    # ==========================================================================
    # Valid CIDR notation
    # ==========================================================================

    def test_valid_cidr_ipv4(self):
        """CIDR notation should be valid."""
        is_valid, error = validate_ip_or_hostname("10.0.0.0/24")
        assert is_valid is True
        assert error == ""

    def test_valid_cidr_ipv6(self):
        """IPv6 CIDR notation should be valid."""
        is_valid, error = validate_ip_or_hostname("2001:db8::/32")
        assert is_valid is True
        assert error == ""

    # ==========================================================================
    # Invalid inputs - empty/null
    # ==========================================================================

    def test_invalid_empty_string(self):
        """Empty string should be invalid."""
        is_valid, error = validate_ip_or_hostname("")
        assert is_valid is False
        assert "empty" in error.lower()

    def test_invalid_none(self):
        """None should be invalid."""
        is_valid, error = validate_ip_or_hostname(None)
        assert is_valid is False

    def test_invalid_non_string(self):
        """Non-string should be invalid."""
        is_valid, error = validate_ip_or_hostname(12345)
        assert is_valid is False
        assert "string" in error.lower()

    # ==========================================================================
    # Shell injection attempts - CRITICAL SECURITY TESTS
    # ==========================================================================

    def test_shell_injection_semicolon(self):
        """Semicolon command separator should be rejected."""
        is_valid, error = validate_ip_or_hostname("8.8.8.8; cat /etc/passwd")
        assert is_valid is False
        assert "Invalid character" in error

    def test_shell_injection_pipe(self):
        """Pipe should be rejected."""
        is_valid, error = validate_ip_or_hostname("8.8.8.8 | rm -rf /")
        assert is_valid is False
        assert "Invalid character" in error

    def test_shell_injection_ampersand(self):
        """Ampersand should be rejected."""
        is_valid, error = validate_ip_or_hostname("8.8.8.8 & whoami")
        assert is_valid is False
        assert "Invalid character" in error

    def test_shell_injection_backtick(self):
        """Backtick command substitution should be rejected."""
        is_valid, error = validate_ip_or_hostname("`whoami`")
        assert is_valid is False
        assert "Invalid character" in error

    def test_shell_injection_dollar_paren(self):
        """Dollar-paren command substitution should be rejected."""
        is_valid, error = validate_ip_or_hostname("$(cat /etc/passwd)")
        assert is_valid is False
        assert "Invalid character" in error

    def test_shell_injection_newline(self):
        """Newline should be rejected."""
        is_valid, error = validate_ip_or_hostname("8.8.8.8\ncat /etc/passwd")
        assert is_valid is False
        assert "Invalid character" in error

    def test_shell_injection_redirect_output(self):
        """Output redirect should be rejected."""
        is_valid, error = validate_ip_or_hostname("8.8.8.8 > /tmp/output")
        assert is_valid is False
        assert "Invalid character" in error

    def test_shell_injection_redirect_input(self):
        """Input redirect should be rejected."""
        is_valid, error = validate_ip_or_hostname("8.8.8.8 < /etc/passwd")
        assert is_valid is False
        assert "Invalid character" in error

    def test_shell_injection_curly_braces(self):
        """Curly braces should be rejected."""
        is_valid, error = validate_ip_or_hostname("8.8.8.8; {cat,/etc/passwd}")
        assert is_valid is False
        assert "Invalid character" in error

    # ==========================================================================
    # Invalid hostname formats
    # ==========================================================================

    def test_invalid_hostname_starts_with_hyphen(self):
        """Hostname starting with hyphen should be invalid."""
        is_valid, error = validate_ip_or_hostname("-invalid")
        assert is_valid is False

    def test_invalid_hostname_ends_with_hyphen(self):
        """Hostname ending with hyphen should be invalid."""
        is_valid, error = validate_ip_or_hostname("invalid-")
        assert is_valid is False

    def test_invalid_hostname_too_long(self):
        """Hostname over 253 chars should be invalid."""
        long_hostname = "a" * 254
        is_valid, error = validate_ip_or_hostname(long_hostname)
        assert is_valid is False
        assert "too long" in error.lower()

    def test_invalid_hostname_with_underscore(self):
        """Hostname with underscore should be invalid (per RFC 1123)."""
        is_valid, error = validate_ip_or_hostname("invalid_hostname")
        assert is_valid is False


class TestValidatePingCount:
    """Tests for ping count validation."""

    # ==========================================================================
    # Valid counts
    # ==========================================================================

    def test_valid_count_minimum(self):
        """Minimum count (1) should be valid."""
        is_valid, count, error = validate_ping_count(1)
        assert is_valid is True
        assert count == 1
        assert error == ""

    def test_valid_count_maximum(self):
        """Maximum count (10) should be valid."""
        is_valid, count, error = validate_ping_count(10)
        assert is_valid is True
        assert count == 10
        assert error == ""

    def test_valid_count_middle(self):
        """Middle values should be valid."""
        is_valid, count, error = validate_ping_count(5)
        assert is_valid is True
        assert count == 5
        assert error == ""

    def test_valid_count_as_string(self):
        """String representation of integer should be valid."""
        is_valid, count, error = validate_ping_count("5")
        assert is_valid is True
        assert count == 5
        assert error == ""

    # ==========================================================================
    # Invalid counts - boundary violations
    # ==========================================================================

    def test_invalid_count_zero(self):
        """Zero should be invalid."""
        is_valid, count, error = validate_ping_count(0)
        assert is_valid is False
        assert "at least 1" in error.lower()

    def test_invalid_count_negative(self):
        """Negative count should be invalid."""
        is_valid, count, error = validate_ping_count(-1)
        assert is_valid is False
        assert "at least 1" in error.lower()

    def test_invalid_count_too_high(self):
        """Count over 10 should be invalid."""
        is_valid, count, error = validate_ping_count(11)
        assert is_valid is False
        assert "at most 10" in error.lower()

    def test_invalid_count_very_high(self):
        """Very high count should be invalid (DoS prevention)."""
        is_valid, count, error = validate_ping_count(1000)
        assert is_valid is False

    # ==========================================================================
    # Invalid counts - type errors
    # ==========================================================================

    def test_invalid_count_not_a_number(self):
        """Non-numeric string should be invalid."""
        is_valid, count, error = validate_ping_count("abc")
        assert is_valid is False
        assert "integer" in error.lower()

    def test_invalid_count_none(self):
        """None should be invalid."""
        is_valid, count, error = validate_ping_count(None)
        assert is_valid is False
        assert "integer" in error.lower()

    def test_invalid_count_float(self):
        """Float should be converted to int."""
        is_valid, count, error = validate_ping_count(5.5)
        assert is_valid is True
        assert count == 5  # Truncated to int

    def test_invalid_count_list(self):
        """List should be invalid."""
        is_valid, count, error = validate_ping_count([5])
        assert is_valid is False


class TestValidationIntegration:
    """Integration tests for validation in ping context."""

    def test_valid_ping_destination_and_count(self):
        """Both destination and count should validate together."""
        dest_valid, _ = validate_ip_or_hostname("198.51.100.1")
        count_valid, count, _ = validate_ping_count(5)
        assert dest_valid is True
        assert count_valid is True
        assert count == 5

    def test_lab_router_loopback(self):
        """Lab router loopback should be valid."""
        is_valid, error = validate_ip_or_hostname("198.51.100.1")  # R1 loopback
        assert is_valid is True

    def test_lab_switch_loopback(self):
        """Lab switch loopback should be valid."""
        is_valid, error = validate_ip_or_hostname("198.51.100.11")  # Switch-R1 loopback
        assert is_valid is True

    def test_containerlab_device_ip(self):
        """Containerlab device IP should be valid."""
        is_valid, error = validate_ip_or_hostname("172.20.20.6")  # edge1
        assert is_valid is True
