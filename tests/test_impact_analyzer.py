"""
Unit tests for Pre-Change Impact Analyzer.

Tests are organized by category as specified in the feature request:
- Platform/Interface Validation (8 tests)
- Current State (2 tests)
- Data Quality - Single Source (5 tests)
- Data Quality - Multi-Source Confidence (6 tests)
- Timeout Behavior (3 tests)
- Rate Limiting (4 tests)
- OSPF Adjacency (4 tests)
- BGP Peer (4 tests)
- Route Impact (4 tests)
- Risk Categorization (5 tests)
- Credential Provider (3 tests)
- Feature Flag (1 test)
- Interface Normalization (5 tests)
- Result Serialization (3 tests)
- Parsers (6 tests)

Total: 63 unit tests
"""

import asyncio
import time
from unittest.mock import Mock, patch, MagicMock, AsyncMock

import pytest

from core.impact_analyzer import (
    ImpactAnalyzer,
    AnalysisStatus,
    Confidence,
    RiskCategory,
    AnalysisResult,
    Impact,
    ImpactSummary,
    OSPFAdjacency,
    BGPPeer,
    AffectedRoute,
    DataSource,
    DataQuality,
    InterfaceState,
    CachedData,
    UNSUPPORTED_INTERFACE_PATTERNS,
    MANAGEMENT_INTERFACE_PATTERNS,
)
from config.readonly_credentials import (
    StaticReadOnlyCredentials,
    validate_credential_provider,
)


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def readonly_creds():
    """Create a valid read-only credential provider."""
    return StaticReadOnlyCredentials(username="readonly", password="readonly123")


@pytest.fixture
def analyzer(readonly_creds):
    """Create an ImpactAnalyzer with mocked config."""
    with patch("core.impact_analyzer.get_impact_analysis_config") as mock_config:
        mock_config.return_value = {
            "enabled": True,
            "supported_platforms": ["cisco_xe"],
            "analysis_timeout_sec": 10,
            "data_max_age_sec": 300,
            "rate_limit_per_user_per_minute": 10,
            "rate_limit_per_device_per_minute": 2,
        }
        yield ImpactAnalyzer(readonly_creds)


@pytest.fixture
def disabled_analyzer(readonly_creds):
    """Create an ImpactAnalyzer with feature disabled."""
    with patch("core.impact_analyzer.get_impact_analysis_config") as mock_config:
        mock_config.return_value = {
            "enabled": False,
            "supported_platforms": ["cisco_xe"],
            "analysis_timeout_sec": 10,
            "data_max_age_sec": 300,
            "rate_limit_per_user_per_minute": 10,
            "rate_limit_per_device_per_minute": 2,
        }
        yield ImpactAnalyzer(readonly_creds)


# =============================================================================
# Platform/Interface Validation Tests (8 tests)
# =============================================================================


class TestPlatformValidation:
    """Tests for platform and interface validation."""

    def test_rejects_non_cisco_device(self, analyzer):
        """Non-Cisco devices should return unsupported status."""
        with patch("core.impact_analyzer.DEVICES", {"edge1": {"device_type": "containerlab_frr"}}):
            with patch("core.impact_analyzer.is_cisco_device", return_value=False):
                result = analyzer.analyze_sync("edge1", "eth0", "shutdown")

        assert result.status == AnalysisStatus.UNSUPPORTED
        assert "cisco" in result.reason.lower() or "containerlab" in result.reason.lower()
        assert result.supported_in == "Future"

    def test_rejects_tunnel_interface(self, analyzer):
        """Tunnel interfaces should return unsupported status."""
        with patch("core.impact_analyzer.DEVICES", {"R1": {"device_type": "cisco_xe"}}):
            with patch("core.impact_analyzer.is_cisco_device", return_value=True):
                result = analyzer.analyze_sync("R1", "Tunnel100", "shutdown")

        assert result.status == AnalysisStatus.UNSUPPORTED
        assert "tunnel" in result.reason.lower() or "dmvpn" in result.reason.lower()
        assert result.supported_in == "Phase 4+"

    def test_rejects_loopback_interface(self, analyzer):
        """Loopback interfaces should return unsupported status."""
        with patch("core.impact_analyzer.DEVICES", {"R1": {"device_type": "cisco_xe"}}):
            with patch("core.impact_analyzer.is_cisco_device", return_value=True):
                result = analyzer.analyze_sync("R1", "Loopback0", "shutdown")

        assert result.status == AnalysisStatus.UNSUPPORTED
        assert "loopback" in result.reason.lower() or "routing identity" in result.reason.lower()
        assert result.supported_in == "Phase 4+"

    def test_rejects_management_interface_gi4(self, analyzer):
        """Router management interface (Gi4) should return unsupported status."""
        with patch("core.impact_analyzer.DEVICES", {"R1": {"device_type": "cisco_xe"}}):
            with patch("core.impact_analyzer.is_cisco_device", return_value=True):
                result = analyzer.analyze_sync("R1", "GigabitEthernet4", "shutdown")

        assert result.status == AnalysisStatus.UNSUPPORTED
        assert "management" in result.reason.lower()
        assert result.supported_in is None  # Never supported

    def test_rejects_management_interface_gi0_0(self, analyzer):
        """Switch management interface (Gi0/0) should return unsupported status."""
        with patch("core.impact_analyzer.DEVICES", {"Switch-R1": {"device_type": "cisco_xe"}}):
            with patch("core.impact_analyzer.is_cisco_device", return_value=True):
                result = analyzer.analyze_sync("Switch-R1", "GigabitEthernet0/0", "shutdown")

        assert result.status == AnalysisStatus.UNSUPPORTED
        assert "management" in result.reason.lower()

    def test_rejects_vlan_interface(self, analyzer):
        """VLAN interfaces (SVIs) should return unsupported status."""
        with patch("core.impact_analyzer.DEVICES", {"Switch-R1": {"device_type": "cisco_xe"}}):
            with patch("core.impact_analyzer.is_cisco_device", return_value=True):
                result = analyzer.analyze_sync("Switch-R1", "Vlan100", "shutdown")

        assert result.status == AnalysisStatus.UNSUPPORTED
        assert "vlan" in result.reason.lower() or "l2" in result.reason.lower()

    def test_accepts_valid_data_interface(self, analyzer):
        """Valid data interfaces should pass validation."""
        with patch("core.impact_analyzer.DEVICES", {"R1": {"device_type": "cisco_xe", "host": "10.0.0.1"}}):
            with patch("core.impact_analyzer.is_cisco_device", return_value=True):
                with patch.object(analyzer, "_collect_all_data") as mock_collect:
                    # Mock data collection to avoid actual SSH
                    mock_collect.return_value = {
                        "interface:GigabitEthernet1": CachedData(
                            data={"status": "up", "ip_address": "10.0.12.1/30"},
                            collected_at=time.time(),
                            status="ok"
                        ),
                        "ospf": CachedData(data=[], collected_at=time.time(), status="ok"),
                        "bgp": CachedData(data={"configured": False}, collected_at=time.time(), status="ok"),
                        "routing": CachedData(data=[], collected_at=time.time(), status="ok"),
                    }
                    result = analyzer.analyze_sync("R1", "GigabitEthernet1", "shutdown")

        # Should not be UNSUPPORTED (validation passed)
        assert result.status != AnalysisStatus.UNSUPPORTED

    def test_rejects_unsupported_command(self, analyzer):
        """Commands other than 'shutdown' should return unsupported status."""
        with patch("core.impact_analyzer.DEVICES", {"R1": {"device_type": "cisco_xe"}}):
            with patch("core.impact_analyzer.is_cisco_device", return_value=True):
                result = analyzer.analyze_sync("R1", "GigabitEthernet1", "no shutdown")

        assert result.status == AnalysisStatus.UNSUPPORTED
        assert "shutdown" in result.reason.lower()


# =============================================================================
# Current State Tests (2 tests)
# =============================================================================


class TestCurrentState:
    """Tests for interface current state handling."""

    def test_returns_no_impact_when_interface_already_down(self, analyzer):
        """Interface already down should return no_impact status."""
        with patch("core.impact_analyzer.DEVICES", {"R1": {"device_type": "cisco_xe", "host": "10.0.0.1"}}):
            with patch("core.impact_analyzer.is_cisco_device", return_value=True):
                with patch.object(analyzer, "_collect_all_data") as mock_collect:
                    mock_collect.return_value = {
                        "interface:GigabitEthernet1": CachedData(
                            data={"status": "administratively down", "ip_address": None},
                            collected_at=time.time(),
                            status="ok"
                        ),
                        "ospf": CachedData(data=[], collected_at=time.time(), status="ok"),
                        "bgp": CachedData(data={"configured": False}, collected_at=time.time(), status="ok"),
                        "routing": CachedData(data=[], collected_at=time.time(), status="ok"),
                    }
                    result = analyzer.analyze_sync("R1", "GigabitEthernet1", "shutdown")

        assert result.status == AnalysisStatus.NO_IMPACT
        assert "already down" in result.reason.lower()

    def test_proceeds_when_interface_is_up(self, analyzer):
        """Interface that is up should proceed with analysis."""
        with patch("core.impact_analyzer.DEVICES", {"R1": {"device_type": "cisco_xe", "host": "10.0.0.1"}}):
            with patch("core.impact_analyzer.is_cisco_device", return_value=True):
                with patch.object(analyzer, "_collect_all_data") as mock_collect:
                    mock_collect.return_value = {
                        "interface:GigabitEthernet1": CachedData(
                            data={"status": "up", "ip_address": "10.0.12.1/30"},
                            collected_at=time.time(),
                            status="ok"
                        ),
                        "ospf": CachedData(data=[], collected_at=time.time(), status="ok"),
                        "bgp": CachedData(data={"configured": False}, collected_at=time.time(), status="ok"),
                        "routing": CachedData(data=[], collected_at=time.time(), status="ok"),
                    }
                    result = analyzer.analyze_sync("R1", "GigabitEthernet1", "shutdown")

        assert result.status == AnalysisStatus.COMPLETED
        assert result.current_state.interface_status == "up"


# =============================================================================
# Data Quality - Single Source Tests (5 tests)
# =============================================================================


class TestDataQualitySingleSource:
    """Tests for single data source quality validation."""

    def test_refuses_when_routing_data_older_than_300_seconds(self, analyzer):
        """Stale routing data should refuse analysis."""
        with patch("core.impact_analyzer.DEVICES", {"R1": {"device_type": "cisco_xe", "host": "10.0.0.1"}}):
            with patch("core.impact_analyzer.is_cisco_device", return_value=True):
                with patch.object(analyzer, "_collect_all_data") as mock_collect:
                    # Routing data is 350 seconds old
                    mock_collect.return_value = {
                        "interface:GigabitEthernet1": CachedData(
                            data={"status": "up"}, collected_at=time.time(), status="ok"
                        ),
                        "ospf": CachedData(data=[], collected_at=time.time(), status="ok"),
                        "bgp": CachedData(data={"configured": False}, collected_at=time.time(), status="ok"),
                        "routing": CachedData(
                            data=[], collected_at=time.time() - 350, status="ok"
                        ),
                    }
                    result = analyzer.analyze_sync("R1", "GigabitEthernet1", "shutdown")

        assert result.status == AnalysisStatus.INSUFFICIENT_DATA
        assert "routing" in result.failed_source or "350" in result.reason

    def test_refuses_when_ospf_data_missing(self, analyzer):
        """Missing OSPF data should refuse analysis."""
        with patch("core.impact_analyzer.DEVICES", {"R1": {"device_type": "cisco_xe", "host": "10.0.0.1"}}):
            with patch("core.impact_analyzer.is_cisco_device", return_value=True):
                with patch.object(analyzer, "_collect_all_data") as mock_collect:
                    mock_collect.return_value = {
                        "interface:GigabitEthernet1": CachedData(
                            data={"status": "up"}, collected_at=time.time(), status="ok"
                        ),
                        "ospf": CachedData(data=None, collected_at=time.time(), status="error", error_message="SSH failed"),
                        "bgp": CachedData(data={"configured": False}, collected_at=time.time(), status="ok"),
                        "routing": CachedData(data=[], collected_at=time.time(), status="ok"),
                    }
                    result = analyzer.analyze_sync("R1", "GigabitEthernet1", "shutdown")

        assert result.status == AnalysisStatus.INSUFFICIENT_DATA
        assert "ospf" in result.failed_source.lower()

    def test_refuses_when_bgp_data_has_error(self, analyzer):
        """BGP data collection error should refuse analysis."""
        with patch("core.impact_analyzer.DEVICES", {"R1": {"device_type": "cisco_xe", "host": "10.0.0.1"}}):
            with patch("core.impact_analyzer.is_cisco_device", return_value=True):
                with patch.object(analyzer, "_collect_all_data") as mock_collect:
                    mock_collect.return_value = {
                        "interface:GigabitEthernet1": CachedData(
                            data={"status": "up"}, collected_at=time.time(), status="ok"
                        ),
                        "ospf": CachedData(data=[], collected_at=time.time(), status="ok"),
                        "bgp": CachedData(data=None, collected_at=time.time(), status="error", error_message="Timeout"),
                        "routing": CachedData(data=[], collected_at=time.time(), status="ok"),
                    }
                    result = analyzer.analyze_sync("R1", "GigabitEthernet1", "shutdown")

        assert result.status == AnalysisStatus.INSUFFICIENT_DATA
        assert "bgp" in result.failed_source.lower()

    def test_proceeds_when_bgp_not_configured(self, analyzer):
        """BGP not configured (but data collected ok) should proceed."""
        with patch("core.impact_analyzer.DEVICES", {"R1": {"device_type": "cisco_xe", "host": "10.0.0.1"}}):
            with patch("core.impact_analyzer.is_cisco_device", return_value=True):
                with patch.object(analyzer, "_collect_all_data") as mock_collect:
                    mock_collect.return_value = {
                        "interface:GigabitEthernet1": CachedData(
                            data={"status": "up", "ip_address": "10.0.12.1/30"},
                            collected_at=time.time(), status="ok"
                        ),
                        "ospf": CachedData(data=[], collected_at=time.time(), status="ok"),
                        "bgp": CachedData(
                            data={"configured": False, "peers": []},
                            collected_at=time.time(), status="ok"
                        ),
                        "routing": CachedData(data=[], collected_at=time.time(), status="ok"),
                    }
                    result = analyzer.analyze_sync("R1", "GigabitEthernet1", "shutdown")

        # Should proceed (BGP data collected successfully, just shows no BGP configured)
        assert result.status == AnalysisStatus.COMPLETED

    def test_refuses_when_interface_state_unavailable(self, analyzer):
        """Unavailable interface state should refuse analysis."""
        with patch("core.impact_analyzer.DEVICES", {"R1": {"device_type": "cisco_xe", "host": "10.0.0.1"}}):
            with patch("core.impact_analyzer.is_cisco_device", return_value=True):
                with patch.object(analyzer, "_collect_all_data") as mock_collect:
                    mock_collect.return_value = {
                        "interface:GigabitEthernet1": CachedData(
                            data=None, collected_at=time.time(), status="error", error_message="Interface not found"
                        ),
                        "ospf": CachedData(data=[], collected_at=time.time(), status="ok"),
                        "bgp": CachedData(data={"configured": False}, collected_at=time.time(), status="ok"),
                        "routing": CachedData(data=[], collected_at=time.time(), status="ok"),
                    }
                    result = analyzer.analyze_sync("R1", "GigabitEthernet1", "shutdown")

        assert result.status == AnalysisStatus.INSUFFICIENT_DATA
        assert "interface" in result.failed_source.lower()


# =============================================================================
# Data Quality - Multi-Source Confidence Tests (6 tests)
# =============================================================================


class TestDataQualityMultiSource:
    """Tests for multi-source data quality and confidence calculation."""

    def test_confidence_high_when_all_sources_under_30s(self, analyzer):
        """All data sources <30s old should give HIGH confidence."""
        data_ages = {"routing": 10, "ospf": 20, "bgp": 25, "interface": 5}
        confidence = analyzer._calculate_confidence(data_ages)
        assert confidence == Confidence.HIGH

    def test_confidence_medium_when_worst_source_45s(self, analyzer):
        """Worst source at 45s should give MEDIUM confidence."""
        data_ages = {"routing": 10, "ospf": 45, "bgp": 20, "interface": 5}
        confidence = analyzer._calculate_confidence(data_ages)
        assert confidence == Confidence.MEDIUM

    def test_confidence_low_when_worst_source_200s(self, analyzer):
        """Worst source at 200s should give LOW confidence."""
        data_ages = {"routing": 10, "ospf": 200, "bgp": 20, "interface": 5}
        confidence = analyzer._calculate_confidence(data_ages)
        assert confidence == Confidence.LOW

    def test_confidence_uses_worst_source_not_average(self, analyzer):
        """Confidence should use WORST source, not average."""
        # Average would be (5+5+5+200)/4 = 53.75s (MEDIUM)
        # But worst is 200s, so should be LOW
        data_ages = {"routing": 5, "ospf": 5, "bgp": 5, "interface": 200}
        confidence = analyzer._calculate_confidence(data_ages)
        assert confidence == Confidence.LOW

    def test_mixed_ages_routing_fresh_ospf_stale_uses_ospf_age(self, analyzer):
        """When routing is fresh but OSPF is stale, use OSPF age."""
        data_ages = {"routing": 5, "ospf": 150}  # OSPF is worst
        confidence = analyzer._calculate_confidence(data_ages)
        assert confidence == Confidence.LOW

    def test_mixed_ages_ospf_fresh_bgp_stale_uses_bgp_age(self, analyzer):
        """When OSPF is fresh but BGP is stale, use BGP age."""
        data_ages = {"routing": 5, "ospf": 10, "bgp": 250}  # BGP is worst
        confidence = analyzer._calculate_confidence(data_ages)
        assert confidence == Confidence.LOW


# =============================================================================
# Timeout Behavior Tests (3 tests)
# =============================================================================


class TestTimeoutBehavior:
    """Tests for analysis timeout handling."""

    def test_returns_timeout_status_when_analysis_exceeds_limit(self, analyzer):
        """Analysis exceeding timeout should return timeout status."""
        with patch("core.impact_analyzer.DEVICES", {"R1": {"device_type": "cisco_xe", "host": "10.0.0.1"}}):
            with patch("core.impact_analyzer.is_cisco_device", return_value=True):
                with patch.object(analyzer, "_collect_all_data") as mock_collect:
                    # Simulate timeout
                    async def slow_collect(*args, **kwargs):
                        raise asyncio.TimeoutError()
                    mock_collect.side_effect = slow_collect

                    result = analyzer.analyze_sync("R1", "GigabitEthernet1", "shutdown")

        assert result.status == AnalysisStatus.TIMEOUT

    def test_timeout_returns_no_partial_results(self, analyzer):
        """Timeout should return no partial results."""
        result = AnalysisResult(
            status=AnalysisStatus.TIMEOUT,
            reason="Analysis did not complete within 10 seconds",
            suggestion="Retry with refresh_data=false",
        )

        d = result.to_dict()
        assert d["partial_results"] is None

    def test_timeout_includes_suggestion(self, analyzer):
        """Timeout should include retry suggestion."""
        result = AnalysisResult(
            status=AnalysisStatus.TIMEOUT,
            reason="Analysis did not complete within 10 seconds",
            suggestion="Retry with refresh_data=false",
        )

        d = result.to_dict()
        assert "suggestion" in d
        assert d["suggestion"] is not None


# =============================================================================
# Rate Limiting Tests (4 tests)
# =============================================================================


class TestRateLimiting:
    """Tests for rate limiting on refresh requests."""

    def test_refresh_rate_limited_per_user(self, analyzer):
        """User should be rate limited after 10 requests per minute."""
        user = "test_user"

        # Simulate 10 requests
        for _ in range(10):
            analyzer._record_user_request(user)

        assert analyzer._is_user_rate_limited(user) is True

    def test_refresh_rate_limited_per_device(self, analyzer):
        """Device should be rate limited after 2 requests per minute."""
        device = "R1"

        # Simulate 2 requests
        analyzer._record_device_request(device)
        analyzer._record_device_request(device)

        assert analyzer._is_device_rate_limited(device) is True

    def test_returns_refresh_in_progress_when_device_busy(self, analyzer):
        """Should return refresh_in_progress when device is already being refreshed."""
        device = "R1"

        # Simulate a lock being held
        lock = analyzer._get_device_lock(device)

        async def hold_lock():
            async with lock:
                # Check while lock is held
                assert analyzer._is_refresh_in_progress(device) is True

        asyncio.get_event_loop().run_until_complete(hold_lock())

    def test_cached_analysis_not_rate_limited(self, analyzer):
        """Analysis without refresh_data should not be rate limited."""
        with patch("core.impact_analyzer.DEVICES", {"R1": {"device_type": "cisco_xe", "host": "10.0.0.1"}}):
            with patch("core.impact_analyzer.is_cisco_device", return_value=True):
                with patch.object(analyzer, "_collect_all_data") as mock_collect:
                    mock_collect.return_value = {
                        "interface:GigabitEthernet1": CachedData(
                            data={"status": "up", "ip_address": "10.0.12.1/30"},
                            collected_at=time.time(), status="ok"
                        ),
                        "ospf": CachedData(data=[], collected_at=time.time(), status="ok"),
                        "bgp": CachedData(data={"configured": False}, collected_at=time.time(), status="ok"),
                        "routing": CachedData(data=[], collected_at=time.time(), status="ok"),
                    }

                    # Fill up the rate limit
                    for _ in range(15):
                        analyzer._record_user_request("test_user")

                    # Should still work without refresh_data=True
                    result = analyzer.analyze_sync(
                        "R1", "GigabitEthernet1", "shutdown",
                        refresh_data=False, user="test_user"
                    )

                    # Should not be rate limited
                    assert result.status != AnalysisStatus.RATE_LIMITED


# =============================================================================
# OSPF Adjacency Tests (4 tests) - Phase 1d
# =============================================================================


class TestOSPFAdjacency:
    """Tests for OSPF adjacency detection."""

    def test_finds_ospf_neighbor_on_interface(self, analyzer):
        """Should find OSPF neighbor on the target interface."""
        ospf_data = CachedData(
            data=[
                {
                    "neighbor_id": "198.51.100.2",
                    "priority": 1,
                    "state": "FULL/DR",
                    "dead_time": "00:00:35",
                    "address": "10.0.12.2",
                    "interface": "GigabitEthernet1",
                }
            ],
            collected_at=time.time(),
            status="ok",
        )

        adjacencies = analyzer._find_ospf_adjacencies_on_interface(
            "GigabitEthernet1", ospf_data
        )

        assert len(adjacencies) == 1
        assert adjacencies[0].neighbor_ip == "10.0.12.2"
        assert adjacencies[0].neighbor_router_id == "198.51.100.2"

    def test_no_false_positive_ospf_neighbor_on_different_interface(self, analyzer):
        """Should not find OSPF neighbor on different interface."""
        ospf_data = CachedData(
            data=[
                {
                    "neighbor_id": "198.51.100.2",
                    "priority": 1,
                    "state": "FULL/DR",
                    "dead_time": "00:00:35",
                    "address": "10.0.12.2",
                    "interface": "GigabitEthernet2",  # Different interface
                }
            ],
            collected_at=time.time(),
            status="ok",
        )

        adjacencies = analyzer._find_ospf_adjacencies_on_interface(
            "GigabitEthernet1", ospf_data
        )

        assert len(adjacencies) == 0

    def test_multiple_ospf_neighbors_on_interface(self, analyzer):
        """Should find multiple OSPF neighbors if present."""
        ospf_data = CachedData(
            data=[
                {
                    "neighbor_id": "198.51.100.2",
                    "priority": 1,
                    "state": "FULL/DR",
                    "dead_time": "00:00:35",
                    "address": "10.0.12.2",
                    "interface": "GigabitEthernet1",
                },
                {
                    "neighbor_id": "198.51.100.3",
                    "priority": 1,
                    "state": "FULL/BDR",
                    "dead_time": "00:00:33",
                    "address": "10.0.12.3",
                    "interface": "GigabitEthernet1",
                },
            ],
            collected_at=time.time(),
            status="ok",
        )

        adjacencies = analyzer._find_ospf_adjacencies_on_interface(
            "GigabitEthernet1", ospf_data
        )

        assert len(adjacencies) == 2
        assert adjacencies[0].neighbor_router_id == "198.51.100.2"
        assert adjacencies[1].neighbor_router_id == "198.51.100.3"

    def test_no_ospf_configured_returns_empty_list(self, analyzer):
        """Should return empty list if no OSPF configured."""
        ospf_data = CachedData(
            data=[],
            collected_at=time.time(),
            status="ok",
        )

        adjacencies = analyzer._find_ospf_adjacencies_on_interface(
            "GigabitEthernet1", ospf_data
        )

        assert len(adjacencies) == 0


# =============================================================================
# BGP Peer Tests (4 tests) - Phase 1d
# =============================================================================


class TestBGPPeer:
    """Tests for BGP peer detection."""

    def test_finds_bgp_peer_with_source_on_interface(self, analyzer):
        """Should find BGP peer using the target interface."""
        bgp_data = CachedData(
            data={
                "configured": True,
                "local_as": 65000,
                "router_id": "198.51.100.1",
                "peers": [
                    {
                        "neighbor": "10.0.12.2",
                        "version": 4,
                        "remote_as": 65000,
                        "uptime": "01:23:45",
                        "state": "Established",
                        "prefixes_received": 5,
                    }
                ],
            },
            collected_at=time.time(),
            status="ok",
        )

        # Interface has IP 10.0.12.1/30 - peer 10.0.12.2 is in same subnet
        peers = analyzer._find_bgp_peers_on_interface(
            "GigabitEthernet1", "10.0.12.1/30", bgp_data
        )

        assert len(peers) == 1
        assert peers[0].peer_ip == "10.0.12.2"
        assert peers[0].peer_asn == 65000

    def test_no_false_positive_bgp_peer_on_different_interface(self, analyzer):
        """Should not find BGP peer on different interface."""
        bgp_data = CachedData(
            data={
                "configured": True,
                "local_as": 65000,
                "router_id": "198.51.100.1",
                "peers": [
                    {
                        "neighbor": "10.0.24.2",  # Different subnet
                        "version": 4,
                        "remote_as": 65000,
                        "uptime": "01:23:45",
                        "state": "Established",
                        "prefixes_received": 5,
                    }
                ],
            },
            collected_at=time.time(),
            status="ok",
        )

        # Interface has IP 10.0.12.1/30 - peer 10.0.24.2 is NOT in same subnet
        peers = analyzer._find_bgp_peers_on_interface(
            "GigabitEthernet1", "10.0.12.1/30", bgp_data
        )

        assert len(peers) == 0

    def test_bgp_not_configured_skips_bgp_analysis(self, analyzer):
        """Should skip BGP analysis if not configured."""
        bgp_data = CachedData(
            data={
                "configured": False,
                "local_as": None,
                "router_id": None,
                "peers": [],
            },
            collected_at=time.time(),
            status="ok",
        )

        peers = analyzer._find_bgp_peers_on_interface(
            "GigabitEthernet1", "10.0.12.1/30", bgp_data
        )

        assert len(peers) == 0

    def test_bgp_configured_but_no_peer_on_interface(self, analyzer):
        """Should return empty list if no BGP peer on interface."""
        bgp_data = CachedData(
            data={
                "configured": True,
                "local_as": 65000,
                "router_id": "198.51.100.1",
                "peers": [
                    {
                        "neighbor": "172.20.20.4",  # Completely different network
                        "version": 4,
                        "remote_as": 65100,
                        "uptime": "00:45:00",
                        "state": "Established",
                        "prefixes_received": 3,
                    }
                ],
            },
            collected_at=time.time(),
            status="ok",
        )

        peers = analyzer._find_bgp_peers_on_interface(
            "GigabitEthernet1", "10.0.12.1/30", bgp_data
        )

        assert len(peers) == 0


# =============================================================================
# Route Impact Tests (4 tests) - Phase 1d
# =============================================================================


class TestRouteImpact:
    """Tests for route impact detection."""

    def test_finds_connected_route_on_interface(self, analyzer):
        """Should find connected route for target interface."""
        routing_data = CachedData(
            data=[
                {
                    "prefix": "10.0.12.0/30",
                    "type": "C",
                    "protocol": "connected",
                    "next_hop": None,
                    "interface": "GigabitEthernet1",
                    "admin_distance": 0,
                    "metric": 0,
                },
                {
                    "prefix": "10.0.12.1/32",
                    "type": "L",  # Local - should be skipped
                    "protocol": "local",
                    "next_hop": None,
                    "interface": "GigabitEthernet1",
                    "admin_distance": 0,
                    "metric": 0,
                },
            ],
            collected_at=time.time(),
            status="ok",
        )

        routes = analyzer._find_affected_routes("GigabitEthernet1", routing_data)

        # Should find connected route but not local route
        assert len(routes) == 1
        assert routes[0].prefix == "10.0.12.0/30"
        assert routes[0].route_type == "connected"

    def test_alternate_exists_when_another_route_in_rib(self, analyzer):
        """Should detect alternate route exists."""
        routing_data = CachedData(
            data=[
                {
                    "prefix": "10.100.0.0/24",
                    "type": "O",
                    "protocol": "ospf",
                    "next_hop": "10.0.12.2",
                    "interface": "GigabitEthernet1",
                    "admin_distance": 110,
                    "metric": 2,
                },
                {
                    "prefix": "10.100.0.0/24",  # Same prefix, different interface
                    "type": "O",
                    "protocol": "ospf",
                    "next_hop": "10.0.13.2",
                    "interface": "GigabitEthernet2",  # Alternate path
                    "admin_distance": 110,
                    "metric": 2,
                },
            ],
            collected_at=time.time(),
            status="ok",
        )

        affected = analyzer._find_affected_routes("GigabitEthernet1", routing_data)
        updated = analyzer._check_alternate_routes(
            affected, routing_data, "GigabitEthernet1"
        )

        assert len(updated) == 1
        assert updated[0].prefix == "10.100.0.0/24"
        assert updated[0].alternate_exists is True

    def test_no_alternate_when_only_route_to_prefix(self, analyzer):
        """Should detect no alternate when only one route."""
        routing_data = CachedData(
            data=[
                {
                    "prefix": "10.0.12.0/30",
                    "type": "C",
                    "protocol": "connected",
                    "next_hop": None,
                    "interface": "GigabitEthernet1",
                    "admin_distance": 0,
                    "metric": 0,
                },
            ],
            collected_at=time.time(),
            status="ok",
        )

        affected = analyzer._find_affected_routes("GigabitEthernet1", routing_data)
        updated = analyzer._check_alternate_routes(
            affected, routing_data, "GigabitEthernet1"
        )

        assert len(updated) == 1
        assert updated[0].prefix == "10.0.12.0/30"
        assert updated[0].alternate_exists is False

    def test_ecmp_one_path_removed_alternate_exists(self, analyzer):
        """ECMP with one path removed should show alternate exists."""
        # Simulating ECMP - two paths to the same destination
        routing_data = CachedData(
            data=[
                {
                    "prefix": "192.168.100.0/24",
                    "type": "O",
                    "protocol": "ospf",
                    "next_hop": "10.0.12.2",
                    "interface": "GigabitEthernet1",
                    "admin_distance": 110,
                    "metric": 20,
                },
                {
                    "prefix": "192.168.100.0/24",  # ECMP - same prefix
                    "type": "O",
                    "protocol": "ospf",
                    "next_hop": "10.0.13.2",
                    "interface": "GigabitEthernet2",
                    "admin_distance": 110,
                    "metric": 20,
                },
                {
                    "prefix": "192.168.100.0/24",  # ECMP - third path
                    "type": "O",
                    "protocol": "ospf",
                    "next_hop": "10.0.14.2",
                    "interface": "GigabitEthernet3",
                    "admin_distance": 110,
                    "metric": 20,
                },
            ],
            collected_at=time.time(),
            status="ok",
        )

        affected = analyzer._find_affected_routes("GigabitEthernet1", routing_data)
        updated = analyzer._check_alternate_routes(
            affected, routing_data, "GigabitEthernet1"
        )

        # Removing Gi1 path - Gi2 and Gi3 are still available
        assert len(updated) == 1
        assert updated[0].prefix == "192.168.100.0/24"
        assert updated[0].alternate_exists is True


# =============================================================================
# Risk Categorization Tests (5 tests)
# =============================================================================


class TestRiskCategorization:
    """Tests for risk categorization logic."""

    def test_no_impact_when_no_adjacencies_no_routes(self, analyzer):
        """No adjacencies or routes affected should be NO_IMPACT."""
        impact = Impact(
            ospf_adjacencies_lost=[],
            bgp_peers_lost=[],
            routes_removed=[],
            summary=ImpactSummary(0, 0, 0, 0),
        )
        risk = analyzer._categorize_risk(impact)
        assert risk == RiskCategory.NO_IMPACT

    def test_low_when_routes_removed_but_alternates_exist(self, analyzer):
        """Routes removed with alternates, no adjacency loss should be LOW."""
        impact = Impact(
            ospf_adjacencies_lost=[],
            bgp_peers_lost=[],
            routes_removed=[
                AffectedRoute("10.0.0.0/24", "connected", alternate_exists=True),
            ],
            summary=ImpactSummary(0, 1, 1, 0),
        )
        risk = analyzer._categorize_risk(impact)
        assert risk == RiskCategory.LOW

    def test_medium_when_adjacency_lost_but_routes_have_alternates(self, analyzer):
        """Adjacency lost but routes have alternates should be MEDIUM."""
        impact = Impact(
            ospf_adjacencies_lost=[
                OSPFAdjacency("10.0.13.1", "198.51.100.1", "R1", "0"),
            ],
            bgp_peers_lost=[],
            routes_removed=[
                AffectedRoute("10.0.13.0/30", "connected", alternate_exists=True),
            ],
            summary=ImpactSummary(1, 1, 1, 0),
        )
        risk = analyzer._categorize_risk(impact)
        assert risk == RiskCategory.MEDIUM

    def test_high_when_route_has_no_alternate(self, analyzer):
        """Route with no alternate path should be HIGH."""
        impact = Impact(
            ospf_adjacencies_lost=[],
            bgp_peers_lost=[],
            routes_removed=[
                AffectedRoute("10.0.0.0/24", "connected", alternate_exists=False),
            ],
            summary=ImpactSummary(0, 1, 0, 1),
        )
        risk = analyzer._categorize_risk(impact)
        assert risk == RiskCategory.HIGH

    def test_critical_when_multiple_adjacencies_lost(self, analyzer):
        """More than 2 adjacencies lost should be CRITICAL."""
        impact = Impact(
            ospf_adjacencies_lost=[
                OSPFAdjacency("10.0.12.1", "198.51.100.1", "R1", "0"),
                OSPFAdjacency("10.0.13.1", "198.51.100.2", "R2", "0"),
                OSPFAdjacency("10.0.14.1", "198.51.100.3", "R3", "0"),
            ],
            bgp_peers_lost=[],
            routes_removed=[],
            summary=ImpactSummary(3, 0, 0, 0),
        )
        risk = analyzer._categorize_risk(impact)
        assert risk == RiskCategory.CRITICAL


# =============================================================================
# Credential Provider Tests
# =============================================================================


class TestCredentialProvider:
    """Tests for credential provider validation."""

    def test_rejects_non_readonly_provider(self):
        """Should reject credential provider that returns is_read_only=False."""

        class FakeProvider:
            def get_username(self):
                return "admin"

            def get_password(self):
                return "admin"

            def get_credentials(self):
                return ("admin", "admin")

            def is_read_only(self):
                return False  # Not read-only!

        with pytest.raises(TypeError) as exc_info:
            validate_credential_provider(FakeProvider())

        assert "is_read_only()" in str(exc_info.value)

    def test_accepts_readonly_provider(self, readonly_creds):
        """Should accept valid read-only credential provider."""
        result = validate_credential_provider(readonly_creds)
        assert result is True

    def test_rejects_provider_missing_methods(self):
        """Should reject provider missing required methods."""

        class IncompleteProvider:
            def get_username(self):
                return "user"
            # Missing other methods

        with pytest.raises(TypeError) as exc_info:
            validate_credential_provider(IncompleteProvider())

        assert "must implement" in str(exc_info.value)


# =============================================================================
# Feature Flag Tests
# =============================================================================


class TestFeatureFlag:
    """Tests for feature flag behavior."""

    def test_returns_unsupported_when_feature_disabled(self, disabled_analyzer):
        """Should return unsupported when feature is disabled."""
        with patch("core.impact_analyzer.DEVICES", {"R1": {"device_type": "cisco_xe"}}):
            result = disabled_analyzer.analyze_sync("R1", "GigabitEthernet1", "shutdown")

        assert result.status == AnalysisStatus.UNSUPPORTED
        assert "disabled" in result.reason.lower()


# =============================================================================
# Interface Normalization Tests
# =============================================================================


class TestInterfaceNormalization:
    """Tests for interface name normalization."""

    def test_normalizes_gi_to_gigabitethernet(self, analyzer):
        """Should normalize Gi1 to GigabitEthernet1."""
        result = analyzer._normalize_interface_name("Gi1")
        assert result == "GigabitEthernet1"

    def test_normalizes_gi_with_slots(self, analyzer):
        """Should normalize Gi1/0/1 to GigabitEthernet1/0/1."""
        result = analyzer._normalize_interface_name("Gi1/0/1")
        assert result == "GigabitEthernet1/0/1"

    def test_preserves_full_name(self, analyzer):
        """Should preserve already-full interface names."""
        result = analyzer._normalize_interface_name("GigabitEthernet1")
        assert result == "GigabitEthernet1"

    def test_normalizes_loopback(self, analyzer):
        """Should normalize Lo0 to Loopback0."""
        result = analyzer._normalize_interface_name("Lo0")
        assert result == "Loopback0"

    def test_normalizes_tunnel(self, analyzer):
        """Should normalize Tu100 to Tunnel100."""
        result = analyzer._normalize_interface_name("Tu100")
        assert result == "Tunnel100"


# =============================================================================
# Result Serialization Tests
# =============================================================================


class TestResultSerialization:
    """Tests for AnalysisResult.to_dict() serialization."""

    def test_completed_result_serializes_correctly(self):
        """Completed result should serialize all fields."""
        result = AnalysisResult(
            status=AnalysisStatus.COMPLETED,
            analysis_id="ia-123456",
            device="R1",
            interface="GigabitEthernet1",
            command="shutdown",
            current_state=InterfaceState("up", "10.0.12.1/30"),
            risk_category=RiskCategory.MEDIUM,
            impact=Impact(
                ospf_adjacencies_lost=[
                    OSPFAdjacency("10.0.12.2", "198.51.100.2", "R2", "0"),
                ],
                bgp_peers_lost=[],
                routes_removed=[
                    AffectedRoute("10.0.12.0/30", "connected", True),
                ],
                summary=ImpactSummary(1, 1, 1, 0),
            ),
            data_quality=DataQuality(
                overall_confidence=Confidence.HIGH,
                worst_data_source="ospf_neighbors",
                worst_data_age_sec=15,
                sources={
                    "routing_table": DataSource(10, "ok"),
                    "ospf_neighbors": DataSource(15, "ok"),
                },
            ),
            warnings=[],
            analysis_duration_ms=850,
        )

        d = result.to_dict()

        assert d["status"] == "completed"
        assert d["analysis_id"] == "ia-123456"
        assert d["device"] == "R1"
        assert d["risk_category"] == "MEDIUM"
        assert len(d["impact"]["ospf_adjacencies_lost"]) == 1
        assert d["data_quality"]["overall_confidence"] == "high"

    def test_unsupported_result_serializes_correctly(self):
        """Unsupported result should serialize reason and supported_in."""
        result = AnalysisResult(
            status=AnalysisStatus.UNSUPPORTED,
            reason="Tunnel interfaces require DMVPN analysis",
            supported_in="Phase 4+",
        )

        d = result.to_dict()

        assert d["status"] == "unsupported"
        assert "reason" in d
        assert d["supported_in"] == "Phase 4+"

    def test_timeout_result_has_null_partial_results(self):
        """Timeout result should have null partial_results."""
        result = AnalysisResult(
            status=AnalysisStatus.TIMEOUT,
            reason="Analysis did not complete within 10 seconds",
            suggestion="Retry with refresh_data=false",
        )

        d = result.to_dict()

        assert d["status"] == "timeout"
        assert d["partial_results"] is None
        assert "suggestion" in d


# =============================================================================
# Parser Tests (Phase 1c)
# =============================================================================


class TestParsers:
    """Tests for command output parsing."""

    def test_parse_interface_state_up(self, analyzer):
        """Should parse interface up state correctly."""
        output = """GigabitEthernet1 is up, line protocol is up
  Hardware is CSR vNIC, address is 5254.0012.0001 (bia 5254.0012.0001)
  Internet address is 10.0.12.1/30
  MTU 1500 bytes, BW 1000000 Kbit/sec, DLY 10 usec,"""

        result = analyzer._parse_interface_state(output)

        assert result["status"] == "up"
        assert result["line_protocol"] == "up"
        assert result["ip_address"] == "10.0.12.1/30"

    def test_parse_interface_state_admin_down(self, analyzer):
        """Should parse administratively down state correctly."""
        output = """GigabitEthernet1 is administratively down, line protocol is down
  Hardware is CSR vNIC, address is 5254.0012.0001 (bia 5254.0012.0001)
  MTU 1500 bytes, BW 1000000 Kbit/sec, DLY 10 usec,"""

        result = analyzer._parse_interface_state(output)

        assert result["status"] == "administratively down"
        assert result["line_protocol"] == "down"
        assert result["ip_address"] is None

    def test_parse_ospf_neighbors(self, analyzer):
        """Should parse OSPF neighbor output correctly."""
        output = """Neighbor ID     Pri   State           Dead Time   Address         Interface
198.51.100.1           1   FULL/DR         00:00:35    10.0.12.1       GigabitEthernet1
198.51.100.2           1   FULL/BDR        00:00:33    10.0.24.2       GigabitEthernet2"""

        neighbors = analyzer._parse_ospf_neighbors(output)

        assert len(neighbors) == 2
        assert neighbors[0]["neighbor_id"] == "198.51.100.1"
        assert neighbors[0]["state"] == "FULL/DR"
        assert neighbors[0]["interface"] == "GigabitEthernet1"
        assert neighbors[1]["neighbor_id"] == "198.51.100.2"

    def test_parse_bgp_summary(self, analyzer):
        """Should parse BGP summary output correctly."""
        output = """BGP router identifier 198.51.100.1, local AS number 65000
BGP table version is 100, main routing table version 100
5 network entries using 1240 bytes of memory

Neighbor        V           AS MsgRcvd MsgSent   TblVer  InQ OutQ Up/Down  State/PfxRcd
10.0.12.2       4        65000    1234    1234      100    0    0 01:23:45        5
172.20.20.4     4        65100     456     789       50    0    0 00:45:00 Idle"""

        result = analyzer._parse_bgp_summary(output)

        assert result["configured"] is True
        assert result["local_as"] == 65000
        assert result["router_id"] == "198.51.100.1"
        assert len(result["peers"]) == 2
        assert result["peers"][0]["state"] == "Established"
        assert result["peers"][0]["prefixes_received"] == 5
        assert result["peers"][1]["state"] == "Idle"

    def test_parse_bgp_summary_not_active(self, analyzer):
        """Should detect BGP not configured."""
        output = """% BGP not active"""

        result = analyzer._parse_bgp_summary(output)

        assert result["configured"] is False
        assert result["peers"] == []

    def test_parse_routing_table(self, analyzer):
        """Should parse routing table correctly."""
        output = """Codes: L - local, C - connected, S - static, O - OSPF, B - BGP

Gateway of last resort is not set

      10.0.0.0/8 is variably subnetted, 10 subnets, 2 masks
C        10.0.12.0/30 is directly connected, GigabitEthernet1
L        10.0.12.1/32 is directly connected, GigabitEthernet1
O        10.0.13.0/30 [110/2] via 10.0.12.2, 01:23:45, GigabitEthernet1
B        172.16.0.0/24 [20/0] via 10.0.12.2, 00:45:00"""

        routes = analyzer._parse_routing_table(output)

        # Should find C, L, O, B routes
        connected = [r for r in routes if r["type"] == "C"]
        local = [r for r in routes if r["type"] == "L"]
        ospf = [r for r in routes if r["type"] == "O"]
        bgp = [r for r in routes if r["type"] == "B"]

        assert len(connected) == 1
        assert connected[0]["prefix"] == "10.0.12.0/30"
        assert connected[0]["interface"] == "GigabitEthernet1"

        assert len(local) == 1
        assert len(ospf) == 1
        assert ospf[0]["next_hop"] == "10.0.12.2"
        assert len(bgp) == 1
