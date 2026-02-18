"""Unit tests for the Tunnel MTU & MSS Calculator."""

import pytest
from core.mtu_calculator import (
    TunnelType,
    EncryptionAlgorithm,
    AuthAlgorithm,
    Platform,
    calculate_mtu,
    generate_config,
    get_common_scenarios,
    calculate_esp_overhead,
    calculate_gre_overhead,
)


class TestOverheadCalculations:
    """Test individual overhead calculations."""

    def test_gre_basic_overhead(self):
        """GRE without options: 4 bytes + 20 byte outer IP = 24 bytes."""
        overhead = calculate_gre_overhead()
        assert overhead == 24

    def test_gre_with_key(self):
        """GRE with key: 4 + 4 + 20 = 28 bytes."""
        overhead = calculate_gre_overhead(with_key=True)
        assert overhead == 28

    def test_gre_with_key_and_sequence(self):
        """GRE with key and sequence: 4 + 4 + 4 + 20 = 32 bytes."""
        overhead = calculate_gre_overhead(with_key=True, with_sequence=True)
        assert overhead == 32

    def test_esp_aes_gcm_tunnel_mode(self):
        """AES-256-GCM in tunnel mode overhead."""
        breakdown = calculate_esp_overhead(
            EncryptionAlgorithm.AES_256_GCM,
            AuthAlgorithm.GCM,
            tunnel_mode=True,
            nat_traversal=False,
        )
        # Outer IP (20) + ESP header (8) + IV (8) + trailer (2) + auth (16) = 54
        assert breakdown.total == 54

    def test_esp_aes_cbc_tunnel_mode(self):
        """AES-256-CBC in tunnel mode overhead."""
        breakdown = calculate_esp_overhead(
            EncryptionAlgorithm.AES_256_CBC,
            AuthAlgorithm.SHA256,
            tunnel_mode=True,
            nat_traversal=False,
        )
        # Outer IP (20) + ESP header (8) + IV (16) + worst padding (15) + trailer (2) + auth (16) = 77
        assert breakdown.total == 77

    def test_esp_with_nat_traversal(self):
        """NAT-T adds 8 bytes UDP header."""
        without_nat = calculate_esp_overhead(
            EncryptionAlgorithm.AES_256_GCM, AuthAlgorithm.GCM, nat_traversal=False
        )
        with_nat = calculate_esp_overhead(
            EncryptionAlgorithm.AES_256_GCM, AuthAlgorithm.GCM, nat_traversal=True
        )
        assert with_nat.total - without_nat.total == 8

    def test_esp_transport_mode(self):
        """Transport mode has no outer IP header."""
        breakdown = calculate_esp_overhead(
            EncryptionAlgorithm.AES_256_GCM,
            AuthAlgorithm.GCM,
            tunnel_mode=False,
        )
        assert breakdown.outer_ip_header == 0


class TestMTUCalculation:
    """Test complete MTU calculations."""

    def test_pure_gre(self):
        """Pure GRE: 1500 - 24 = 1476 MTU."""
        result = calculate_mtu(TunnelType.GRE)
        assert result.tunnel_mtu == 1476
        assert result.tcp_mss == 1436  # 1476 - 40 (IP + TCP headers)
        assert result.total_overhead == 24

    def test_gre_ipsec_gcm(self):
        """GRE over IPsec (DMVPN) with AES-GCM."""
        result = calculate_mtu(
            TunnelType.GRE_IPSEC,
            encryption=EncryptionAlgorithm.AES_256_GCM,
            auth=AuthAlgorithm.GCM,
        )
        # GRE (4) + ESP header (8) + IV (8) + trailer (2) + auth (16) + outer IP (20) = 58
        assert result.total_overhead == 58
        assert result.tunnel_mtu == 1442
        assert result.tcp_mss == 1402

    def test_ipsec_tunnel_cbc(self):
        """IPsec tunnel mode with AES-CBC."""
        result = calculate_mtu(
            TunnelType.IPSEC_TUNNEL,
            encryption=EncryptionAlgorithm.AES_256_CBC,
            auth=AuthAlgorithm.SHA256,
        )
        # ESP header (8) + IV (16) + worst padding (15) + trailer (2) + auth (16) + outer IP (20) = 77
        assert result.total_overhead == 77
        assert result.tunnel_mtu == 1423

    def test_vxlan(self):
        """VXLAN: 50 byte overhead."""
        result = calculate_mtu(TunnelType.VXLAN)
        # Outer IP (20) + UDP (8) + VXLAN (8) = 36
        assert result.total_overhead == 36
        assert result.tunnel_mtu == 1464

    def test_wireguard(self):
        """WireGuard overhead."""
        result = calculate_mtu(TunnelType.WIREGUARD)
        # Outer IP (20) + UDP (8) + WG header (32) + auth tag (16) = 76
        assert result.total_overhead == 76
        assert result.tunnel_mtu == 1424

    def test_custom_physical_mtu(self):
        """Custom physical MTU (e.g., jumbo frames)."""
        result = calculate_mtu(TunnelType.GRE, physical_mtu=9000)
        assert result.tunnel_mtu == 8976  # 9000 - 24
        assert result.tcp_mss == 8936  # 8976 - 40

    def test_nat_traversal_adds_8_bytes(self):
        """NAT-T adds 8 bytes UDP encapsulation."""
        without_nat = calculate_mtu(
            TunnelType.GRE_IPSEC,
            encryption=EncryptionAlgorithm.AES_256_GCM,
            nat_traversal=False,
        )
        with_nat = calculate_mtu(
            TunnelType.GRE_IPSEC,
            encryption=EncryptionAlgorithm.AES_256_GCM,
            nat_traversal=True,
        )
        assert with_nat.total_overhead - without_nat.total_overhead == 8
        assert with_nat.tunnel_mtu == without_nat.tunnel_mtu - 8

    def test_defaults_to_aes_gcm(self):
        """IPsec tunnels default to AES-256-GCM."""
        result = calculate_mtu(TunnelType.GRE_IPSEC)
        assert result.encryption == "aes-256-gcm"
        assert "Using default encryption" in result.warnings[0]

    def test_low_mtu_warning(self):
        """Warning when MTU falls below IPv4/IPv6 minimums."""
        result = calculate_mtu(TunnelType.GRE_IPSEC, physical_mtu=600)
        assert any("below IPv4 minimum" in w for w in result.warnings)


class TestConfigGeneration:
    """Test platform-specific config generation."""

    @pytest.fixture
    def dmvpn_result(self):
        return calculate_mtu(
            TunnelType.GRE_IPSEC,
            encryption=EncryptionAlgorithm.AES_256_GCM,
        )

    def test_cisco_ios_config(self, dmvpn_result):
        config = generate_config(dmvpn_result, Platform.CISCO_IOS, "Tunnel100")
        assert "interface Tunnel100" in config
        assert "ip mtu 1442" in config
        assert "ip tcp adjust-mss 1402" in config

    def test_cisco_asa_config(self, dmvpn_result):
        config = generate_config(dmvpn_result, Platform.CISCO_ASA, "outside")
        assert "mtu outside 1442" in config
        assert "sysopt connection tcpmss 1402" in config

    def test_juniper_config(self, dmvpn_result):
        config = generate_config(dmvpn_result, Platform.JUNIPER_JUNOS, "st0.0")
        assert "set interfaces st0.0 mtu 1442" in config
        assert "set security flow tcp-mss ipsec-vpn mss 1402" in config

    def test_palo_alto_config(self, dmvpn_result):
        config = generate_config(dmvpn_result, Platform.PALO_ALTO, "tunnel.1")
        assert "mtu 1442" in config
        assert "1402" in config

    def test_fortinet_config(self, dmvpn_result):
        config = generate_config(dmvpn_result, Platform.FORTINET, "vpn-tunnel")
        assert "tcp-mss 1402" in config

    def test_linux_config(self, dmvpn_result):
        config = generate_config(dmvpn_result, Platform.LINUX, "tun0")
        assert "ip link set dev tun0 mtu 1442" in config
        assert "iptables" in config
        assert "--set-mss 1402" in config

    def test_cisco_nxos_config(self, dmvpn_result):
        config = generate_config(dmvpn_result, Platform.CISCO_NXOS, "Tunnel1")
        assert "interface Tunnel1" in config
        assert "mtu 1442" in config
        assert "ip tcp adjust-mss 1402" in config

    def test_nokia_srlinux_config(self, dmvpn_result):
        config = generate_config(dmvpn_result, Platform.NOKIA_SRLINUX, "ethernet-1/1")
        assert "set / interface ethernet-1/1 mtu 1442" in config
        assert "1402" in config

    def test_nokia_sros_config(self, dmvpn_result):
        config = generate_config(dmvpn_result, Platform.NOKIA_SROS, "to-peer")
        assert "ip-mtu 1442" in config
        assert "tcp-mss-adjust 1402" in config

    def test_arista_eos_config(self, dmvpn_result):
        config = generate_config(dmvpn_result, Platform.ARISTA_EOS, "Tunnel1")
        assert "interface Tunnel1" in config
        assert "mtu 1442" in config
        assert "ip tcp mss ceiling 1402" in config

    def test_mikrotik_config(self, dmvpn_result):
        config = generate_config(dmvpn_result, Platform.MIKROTIK, "gre-tunnel1")
        assert "mtu=1442" in config
        assert "new-mss=1402" in config
        assert "change-mss" in config

    def test_huawei_vrp_config(self, dmvpn_result):
        config = generate_config(dmvpn_result, Platform.HUAWEI_VRP, "Tunnel0/0/1")
        assert "interface Tunnel0/0/1" in config
        assert "mtu 1442" in config
        assert "tcp adjust-mss 1402" in config

    def test_vyos_config(self, dmvpn_result):
        config = generate_config(dmvpn_result, Platform.VYOS, "tun0")
        assert "set interfaces tunnel tun0 mtu 1442" in config
        assert "adjust-mss 1402" in config


class TestCommonScenarios:
    """Test pre-calculated common scenarios."""

    def test_scenarios_returned(self):
        scenarios = get_common_scenarios()
        assert "dmvpn_aes256gcm" in scenarios
        assert "dmvpn_nat_t" in scenarios
        assert "ipsec_s2s" in scenarios
        assert "gre_only" in scenarios
        assert "vxlan" in scenarios
        assert "wireguard" in scenarios

    def test_scenario_structure(self):
        scenarios = get_common_scenarios()
        for key, scenario in scenarios.items():
            assert "name" in scenario
            assert "tunnel_mtu" in scenario
            assert "tcp_mss" in scenario
            assert "overhead" in scenario
            # Verify sanity
            assert 1000 < scenario["tunnel_mtu"] < 1500
            assert scenario["tcp_mss"] == scenario["tunnel_mtu"] - 40


class TestOverheadBreakdown:
    """Test overhead breakdown details."""

    def test_breakdown_components(self):
        result = calculate_mtu(
            TunnelType.GRE_IPSEC,
            encryption=EncryptionAlgorithm.AES_256_GCM,
        )
        breakdown = result.breakdown.to_dict()
        assert "Outer IP Header" in breakdown
        assert "GRE Header" in breakdown
        assert "ESP Header (SPI+Seq)" in breakdown
        assert "ESP IV" in breakdown
        assert "ESP Auth (ICV)" in breakdown
        assert "Total Overhead" in breakdown

    def test_result_to_dict(self):
        result = calculate_mtu(TunnelType.GRE)
        d = result.to_dict()
        assert d["physical_mtu"] == 1500
        assert d["tunnel_mtu"] == 1476
        assert d["tcp_mss"] == 1436
        assert d["total_overhead"] == 24
        assert "overhead_breakdown" in d
