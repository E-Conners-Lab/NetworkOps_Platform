"""
Pre-Change Adjacency & Route Impact Checker.

Analyzes single-interface shutdown impact on network devices.
Reports direct adjacency losses and directly connected route removals.

SUPPORTED PLATFORMS (Phase 2):
- Cisco IOS-XE (C8000V, CSR, Cat9k)
- FRR (Free Range Routing) via vtysh
- Nokia SR Linux (planned)
- Arista EOS (planned)

LIMITATIONS:
- Single interface shutdown only
- No path computation
- No VRF support
- No tunnel/loopback/management interfaces
- No multi-command analysis

SECURITY DESIGN:
This module uses READ-ONLY CREDENTIALS and cannot make configuration changes.
The ImpactAnalyzer type-checks that the credential provider is read-only at init.
"""

import re
import time
import asyncio
import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, Union

from scrapli.driver.core import AsyncIOSXEDriver
from scrapli.driver import AsyncGenericDriver

from config.readonly_credentials import (
    ReadOnlyCredentialProvider,
    validate_credential_provider,
    get_readonly_credentials,
)
from config.devices import DEVICES, is_cisco_device, SSH_STRICT_KEY
from core.feature_flags import get_impact_analysis_config
from core.containerlab import get_containerlab_command_output

logger = logging.getLogger(__name__)


# =============================================================================
# Data Types
# =============================================================================


class AnalysisStatus(Enum):
    """Status codes for impact analysis."""

    COMPLETED = "completed"
    NO_IMPACT = "no_impact"
    UNSUPPORTED = "unsupported"
    INSUFFICIENT_DATA = "insufficient_data"
    TIMEOUT = "timeout"
    RATE_LIMITED = "rate_limited"
    REFRESH_IN_PROGRESS = "refresh_in_progress"


class Confidence(Enum):
    """Data quality confidence levels."""

    HIGH = "high"  # All data <30s old
    MEDIUM = "medium"  # Worst data 30-120s old
    LOW = "low"  # Worst data 120-300s old
    REFUSED = "refused"  # Any data >300s or missing


class RiskCategory(Enum):
    """Risk categorization (NOT scoring)."""

    NO_IMPACT = "NO_IMPACT"  # Interface already down, or no adjacencies/routes
    LOW = "LOW"  # Routes removed but all have alternates, no adjacency loss
    MEDIUM = "MEDIUM"  # 1+ adjacency lost, all affected routes have alternates
    HIGH = "HIGH"  # 1+ route with no alternate path
    CRITICAL = "CRITICAL"  # >2 adjacencies lost on single interface


@dataclass
class OSPFAdjacency:
    """OSPF neighbor that would be lost."""

    neighbor_ip: str
    neighbor_router_id: str
    neighbor_device: Optional[str]  # Device name if known
    area: str


@dataclass
class BGPPeer:
    """BGP peer that would be lost."""

    peer_ip: str
    peer_asn: int
    peer_device: Optional[str]


@dataclass
class AffectedRoute:
    """Route that would be removed."""

    prefix: str
    route_type: str  # "connected", "ospf", "bgp", etc.
    alternate_exists: bool


@dataclass
class DataSource:
    """Information about a data source."""

    age_sec: int
    status: str  # "ok", "stale", "missing", "error"


@dataclass
class CachedData:
    """Cached data with collection timestamp."""

    data: dict | list | str | None
    collected_at: float  # time.time() when collected
    status: str  # "ok", "error", "missing"
    error_message: Optional[str] = None

    @property
    def age_sec(self) -> int:
        """Age in seconds since collection."""
        return int(time.time() - self.collected_at)

    def to_data_source(self) -> DataSource:
        """Convert to DataSource for reporting."""
        return DataSource(
            age_sec=self.age_sec,
            status=self.status if self.status != "ok" else (
                "stale" if self.age_sec > 300 else "ok"
            ),
        )


@dataclass
class DataQuality:
    """Data quality information for the analysis."""

    overall_confidence: Confidence
    worst_data_source: str
    worst_data_age_sec: int
    sources: dict  # source_name -> DataSource


@dataclass
class InterfaceState:
    """Current state of the target interface."""

    interface_status: str  # "up", "down", "administratively down"
    ip_address: Optional[str]


@dataclass
class ImpactSummary:
    """Summary of impact counts."""

    adjacencies_affected: int
    routes_affected: int
    routes_with_alternate: int
    routes_without_alternate: int


@dataclass
class Impact:
    """Full impact details."""

    ospf_adjacencies_lost: list[OSPFAdjacency] = field(default_factory=list)
    bgp_peers_lost: list[BGPPeer] = field(default_factory=list)
    routes_removed: list[AffectedRoute] = field(default_factory=list)
    summary: ImpactSummary = field(default_factory=lambda: ImpactSummary(0, 0, 0, 0))


@dataclass
class AnalysisResult:
    """Complete analysis result."""

    status: AnalysisStatus
    analysis_id: Optional[str] = None
    device: Optional[str] = None
    interface: Optional[str] = None
    command: Optional[str] = None

    # For successful analysis
    current_state: Optional[InterfaceState] = None
    risk_category: Optional[RiskCategory] = None
    impact: Optional[Impact] = None
    data_quality: Optional[DataQuality] = None
    warnings: list[str] = field(default_factory=list)
    analysis_duration_ms: int = 0

    # For unsupported/error cases
    reason: Optional[str] = None
    supported_in: Optional[str] = None
    failed_source: Optional[str] = None
    suggestion: Optional[str] = None
    retry_after_sec: Optional[int] = None
    partial_results: Optional[dict] = None

    def to_dict(self) -> dict:
        """Convert to JSON-serializable dict."""
        result = {
            "status": self.status.value,
        }

        if self.status == AnalysisStatus.COMPLETED:
            result.update({
                "analysis_id": self.analysis_id,
                "device": self.device,
                "interface": self.interface,
                "command": self.command,
                "current_state": {
                    "interface_status": self.current_state.interface_status,
                    "ip_address": self.current_state.ip_address,
                } if self.current_state else None,
                "risk_category": self.risk_category.value if self.risk_category else None,
                "impact": self._impact_to_dict(),
                "data_quality": self._data_quality_to_dict(),
                "warnings": self.warnings,
                "analysis_duration_ms": self.analysis_duration_ms,
            })
        elif self.status == AnalysisStatus.NO_IMPACT:
            result.update({
                "analysis_id": self.analysis_id,
                "device": self.device,
                "interface": self.interface,
                "command": self.command,
                "current_state": {
                    "interface_status": self.current_state.interface_status,
                    "ip_address": self.current_state.ip_address,
                } if self.current_state else None,
                "risk_category": RiskCategory.NO_IMPACT.value,
                "reason": self.reason,
                "analysis_duration_ms": self.analysis_duration_ms,
            })
        elif self.status == AnalysisStatus.UNSUPPORTED:
            result.update({
                "reason": self.reason,
                "supported_in": self.supported_in,
            })
        elif self.status == AnalysisStatus.INSUFFICIENT_DATA:
            result.update({
                "reason": self.reason,
                "failed_source": self.failed_source,
                "suggestion": self.suggestion,
            })
        elif self.status == AnalysisStatus.TIMEOUT:
            result.update({
                "reason": self.reason,
                "partial_results": None,  # Explicitly null, never partial
                "suggestion": self.suggestion,
            })
        elif self.status in (AnalysisStatus.RATE_LIMITED, AnalysisStatus.REFRESH_IN_PROGRESS):
            result.update({
                "reason": self.reason,
                "retry_after_sec": self.retry_after_sec,
            })

        return result

    def _impact_to_dict(self) -> Optional[dict]:
        """Convert impact to dict."""
        if self.impact is None:
            return None

        return {
            "ospf_adjacencies_lost": [
                {
                    "neighbor_ip": adj.neighbor_ip,
                    "neighbor_router_id": adj.neighbor_router_id,
                    "neighbor_device": adj.neighbor_device,
                    "area": adj.area,
                }
                for adj in self.impact.ospf_adjacencies_lost
            ],
            "bgp_peers_lost": [
                {
                    "peer_ip": peer.peer_ip,
                    "peer_asn": peer.peer_asn,
                    "peer_device": peer.peer_device,
                }
                for peer in self.impact.bgp_peers_lost
            ],
            "routes_removed": [
                {
                    "prefix": route.prefix,
                    "type": route.route_type,
                    "alternate_exists": route.alternate_exists,
                }
                for route in self.impact.routes_removed
            ],
            "summary": {
                "adjacencies_affected": self.impact.summary.adjacencies_affected,
                "routes_affected": self.impact.summary.routes_affected,
                "routes_with_alternate": self.impact.summary.routes_with_alternate,
                "routes_without_alternate": self.impact.summary.routes_without_alternate,
            },
        }

    def _data_quality_to_dict(self) -> Optional[dict]:
        """Convert data quality to dict."""
        if self.data_quality is None:
            return None

        return {
            "overall_confidence": self.data_quality.overall_confidence.value,
            "worst_data_source": self.data_quality.worst_data_source,
            "worst_data_age_sec": self.data_quality.worst_data_age_sec,
            "sources": {
                name: {"age_sec": src.age_sec, "status": src.status}
                for name, src in self.data_quality.sources.items()
            },
        }


# =============================================================================
# Interface Patterns
# =============================================================================

# Unsupported interface patterns
UNSUPPORTED_INTERFACE_PATTERNS = [
    # Tunnel interfaces (DMVPN, IPsec, GRE)
    (r"^Tunnel\d+$", "Tunnel interfaces require DMVPN state analysis", "Phase 4+"),
    # Loopback interfaces
    (r"^Loopback\d+$", "Loopback interfaces affect routing identity", "Phase 4+"),
    # VLAN interfaces (SVIs)
    (r"^Vlan\d+$", "VLAN interfaces (SVIs) require L2 topology analysis", "Phase 3+"),
    # BDI interfaces
    (r"^BDI\d+$", "Bridge Domain interfaces require L2 analysis", "Phase 3+"),
    # NVE (VXLAN) interfaces
    (r"^nve\d+$", "NVE interfaces require overlay analysis", "Phase 4+"),
    # Null interface
    (r"^Null\d+$", "Null interfaces have no impact", None),
]

# Management interface patterns (by device type)
MANAGEMENT_INTERFACE_PATTERNS = {
    # Routers: GigabitEthernet4 is management
    "router": [r"^GigabitEthernet4$", r"^Gi4$"],
    # Switches: GigabitEthernet0/0 (in VRF Mgmt-vrf) is management
    "switch": [r"^GigabitEthernet0/0$", r"^Gi0/0$"],
}

# Supported commands (Phase 1: shutdown only)
SUPPORTED_COMMANDS = ["shutdown"]


# =============================================================================
# Impact Analyzer
# =============================================================================


class ImpactAnalyzer:
    """
    Analyzes single-interface shutdown impact on Cisco IOS-XE devices.

    USES READ-ONLY CREDENTIALS. Cannot make configuration changes by design.

    LIMITATIONS:
    - Cisco IOS-XE only
    - Single interface shutdown only
    - No path computation
    - No VRF support
    - No tunnel/loopback/management interfaces
    """

    def __init__(self, credential_provider: Optional[ReadOnlyCredentialProvider] = None):
        """Initialize the impact analyzer.

        Args:
            credential_provider: Must provide read-only credentials only.
                                 If None, uses default VaultReadOnlyCredentials.

        Raises:
            TypeError: If provider doesn't implement ReadOnlyCredentialProvider
        """
        if credential_provider is None:
            credential_provider = get_readonly_credentials()

        # Validate credential provider is read-only
        validate_credential_provider(credential_provider)

        self._credentials = credential_provider
        self._config = get_impact_analysis_config()

        # Rate limiting state
        self._user_request_times: dict[str, list[float]] = {}
        self._device_request_times: dict[str, list[float]] = {}
        self._device_refresh_locks: dict[str, asyncio.Lock] = {}

        # Data cache: device -> source_name -> CachedData
        self._data_cache: dict[str, dict[str, CachedData]] = {}

        logger.info(
            f"ImpactAnalyzer initialized with config: "
            f"timeout={self._config['analysis_timeout_sec']}s, "
            f"max_age={self._config['data_max_age_sec']}s"
        )

    # =========================================================================
    # Validation Methods (Phase 1b)
    # =========================================================================

    def _validate_platform(self, device: str) -> Optional[AnalysisResult]:
        """Validate device platform is supported.

        Args:
            device: Device name

        Returns:
            AnalysisResult with unsupported status if invalid, None if valid
        """
        if device not in DEVICES:
            return AnalysisResult(
                status=AnalysisStatus.UNSUPPORTED,
                reason=f"Device '{device}' not found in inventory",
                supported_in=None,
            )

        # Get normalized platform
        platform = self._get_device_platform(device)

        # Check if it's in the supported platforms list
        supported = self._config.get("supported_platforms", ["cisco_xe"])

        if platform not in supported:
            return AnalysisResult(
                status=AnalysisStatus.UNSUPPORTED,
                reason=f"Platform '{platform}' not in supported platforms: {supported}",
                supported_in="Phase 3+" if platform == "srlinux" else "Future",
            )

        return None  # Valid

    def _validate_interface(self, device: str, interface: str) -> Optional[AnalysisResult]:
        """Validate interface is supported for analysis.

        Args:
            device: Device name
            interface: Interface name

        Returns:
            AnalysisResult with unsupported status if invalid, None if valid
        """
        # Normalize interface name
        normalized = self._normalize_interface_name(interface)

        # Check against unsupported patterns
        for pattern, reason, supported_in in UNSUPPORTED_INTERFACE_PATTERNS:
            if re.match(pattern, normalized, re.IGNORECASE):
                return AnalysisResult(
                    status=AnalysisStatus.UNSUPPORTED,
                    reason=reason,
                    supported_in=supported_in,
                )

        # Check for management interfaces
        is_switch = device.lower().startswith("switch")
        mgmt_patterns = MANAGEMENT_INTERFACE_PATTERNS.get(
            "switch" if is_switch else "router", []
        )

        for pattern in mgmt_patterns:
            if re.match(pattern, normalized, re.IGNORECASE):
                return AnalysisResult(
                    status=AnalysisStatus.UNSUPPORTED,
                    reason="Management interfaces are out-of-band and excluded from analysis",
                    supported_in=None,
                )

        return None  # Valid

    def _validate_command(self, command: str) -> Optional[AnalysisResult]:
        """Validate command is supported.

        Args:
            command: Command to validate

        Returns:
            AnalysisResult with unsupported status if invalid, None if valid
        """
        normalized = command.strip().lower()

        if normalized not in SUPPORTED_COMMANDS:
            return AnalysisResult(
                status=AnalysisStatus.UNSUPPORTED,
                reason=f"Command '{command}' not supported. Only 'shutdown' is supported.",
                supported_in="Phase 3+",
            )

        return None  # Valid

    def _normalize_interface_name(self, interface: str) -> str:
        """Normalize interface name to full form.

        Args:
            interface: Short or full interface name

        Returns:
            Normalized full interface name
        """
        # Common abbreviations
        abbreviations = {
            r"^Gi(\d)$": r"GigabitEthernet\1",
            r"^Gi(\d+)/(\d+)/(\d+)$": r"GigabitEthernet\1/\2/\3",
            r"^Gi(\d+)/(\d+)$": r"GigabitEthernet\1/\2",
            r"^Te(\d)$": r"TenGigabitEthernet\1",
            r"^Te(\d+)/(\d+)/(\d+)$": r"TenGigabitEthernet\1/\2/\3",
            r"^Fa(\d)$": r"FastEthernet\1",
            r"^Fa(\d+)/(\d+)$": r"FastEthernet\1/\2",
            r"^Lo(\d+)$": r"Loopback\1",
            r"^Tu(\d+)$": r"Tunnel\1",
            r"^Vl(\d+)$": r"Vlan\1",
        }

        for pattern, replacement in abbreviations.items():
            if re.match(pattern, interface, re.IGNORECASE):
                return re.sub(pattern, replacement, interface, flags=re.IGNORECASE)

        return interface

    # =========================================================================
    # Rate Limiting Methods
    # =========================================================================

    def _is_user_rate_limited(self, user: str) -> bool:
        """Check if user has exceeded rate limit.

        Args:
            user: User identifier

        Returns:
            True if rate limited
        """
        now = time.time()
        limit = self._config.get("rate_limit_per_user_per_minute", 10)

        # Get/create request times list
        if user not in self._user_request_times:
            self._user_request_times[user] = []

        # Remove old entries (older than 60 seconds)
        self._user_request_times[user] = [
            t for t in self._user_request_times[user] if now - t < 60
        ]

        return len(self._user_request_times[user]) >= limit

    def _is_device_rate_limited(self, device: str) -> bool:
        """Check if device has exceeded refresh rate limit.

        Args:
            device: Device name

        Returns:
            True if rate limited
        """
        now = time.time()
        limit = self._config.get("rate_limit_per_device_per_minute", 2)

        if device not in self._device_request_times:
            self._device_request_times[device] = []

        self._device_request_times[device] = [
            t for t in self._device_request_times[device] if now - t < 60
        ]

        return len(self._device_request_times[device]) >= limit

    def _record_user_request(self, user: str) -> None:
        """Record a user request for rate limiting."""
        now = time.time()
        if user not in self._user_request_times:
            self._user_request_times[user] = []
        self._user_request_times[user].append(now)

    def _record_device_request(self, device: str) -> None:
        """Record a device request for rate limiting."""
        now = time.time()
        if device not in self._device_request_times:
            self._device_request_times[device] = []
        self._device_request_times[device].append(now)

    def _is_refresh_in_progress(self, device: str) -> bool:
        """Check if a refresh is already in progress for device.

        Args:
            device: Device name

        Returns:
            True if refresh in progress
        """
        lock = self._device_refresh_locks.get(device)
        return lock is not None and lock.locked()

    def _get_device_lock(self, device: str) -> asyncio.Lock:
        """Get or create lock for device refresh serialization."""
        if device not in self._device_refresh_locks:
            self._device_refresh_locks[device] = asyncio.Lock()
        return self._device_refresh_locks[device]

    # =========================================================================
    # Data Quality Methods
    # =========================================================================

    def _calculate_confidence(self, data_ages: dict[str, int]) -> Confidence:
        """Calculate overall confidence from data ages.

        Rule: Use the WORST (oldest) age among all required data sources.

        Args:
            data_ages: Dict of source_name -> age in seconds

        Returns:
            Confidence level
        """
        if not data_ages:
            return Confidence.REFUSED

        worst_age = max(data_ages.values())
        max_age = self._config.get("data_max_age_sec", 300)

        if worst_age > max_age:
            return Confidence.REFUSED
        elif worst_age > 120:
            return Confidence.LOW
        elif worst_age > 30:
            return Confidence.MEDIUM
        else:
            return Confidence.HIGH

    def _build_data_quality(
        self, sources: dict[str, DataSource]
    ) -> tuple[DataQuality, Optional[AnalysisResult]]:
        """Build DataQuality from sources and check if analysis should proceed.

        Args:
            sources: Dict of source_name -> DataSource

        Returns:
            Tuple of (DataQuality, Optional[AnalysisResult if should refuse])
        """
        data_ages = {name: src.age_sec for name, src in sources.items() if src.status == "ok"}
        failed_sources = {name: src for name, src in sources.items() if src.status != "ok"}

        # Check for missing required data
        if failed_sources:
            first_failed = list(failed_sources.keys())[0]
            first_error = failed_sources[first_failed]
            return (
                DataQuality(
                    overall_confidence=Confidence.REFUSED,
                    worst_data_source=first_failed,
                    worst_data_age_sec=first_error.age_sec,
                    sources=sources,
                ),
                AnalysisResult(
                    status=AnalysisStatus.INSUFFICIENT_DATA,
                    reason=f"Data source '{first_failed}' is {first_error.status}",
                    failed_source=first_failed,
                    suggestion="Click 'Refresh Data' to collect current state",
                ),
            )

        confidence = self._calculate_confidence(data_ages)

        if confidence == Confidence.REFUSED:
            worst_source = max(data_ages, key=data_ages.get)
            worst_age = data_ages[worst_source]
            max_age = self._config.get("data_max_age_sec", 300)
            return (
                DataQuality(
                    overall_confidence=Confidence.REFUSED,
                    worst_data_source=worst_source,
                    worst_data_age_sec=worst_age,
                    sources=sources,
                ),
                AnalysisResult(
                    status=AnalysisStatus.INSUFFICIENT_DATA,
                    reason=f"Data source '{worst_source}' is {worst_age} seconds old (max: {max_age}s)",
                    failed_source=worst_source,
                    suggestion="Click 'Refresh Data' to collect current state",
                ),
            )

        # Find worst source for reporting
        worst_source = max(data_ages, key=data_ages.get) if data_ages else "unknown"
        worst_age = data_ages.get(worst_source, 0)

        return (
            DataQuality(
                overall_confidence=confidence,
                worst_data_source=worst_source,
                worst_data_age_sec=worst_age,
                sources=sources,
            ),
            None,  # OK to proceed
        )

    # =========================================================================
    # Risk Categorization
    # =========================================================================

    def _categorize_risk(self, impact: Impact) -> RiskCategory:
        """Categorize risk based on impact.

        Args:
            impact: Impact details

        Returns:
            RiskCategory
        """
        total_adjacencies = (
            len(impact.ospf_adjacencies_lost) + len(impact.bgp_peers_lost)
        )
        routes_without_alternate = impact.summary.routes_without_alternate

        if total_adjacencies == 0 and impact.summary.routes_affected == 0:
            return RiskCategory.NO_IMPACT
        elif total_adjacencies > 2:
            return RiskCategory.CRITICAL
        elif routes_without_alternate > 0:
            return RiskCategory.HIGH
        elif total_adjacencies > 0:
            return RiskCategory.MEDIUM
        else:
            # Routes removed but all have alternates
            return RiskCategory.LOW

    # =========================================================================
    # Data Collection Methods (Phase 1c)
    # =========================================================================

    def _get_device_platform(self, device: str) -> str:
        """Determine the platform type for a device.

        Returns:
            Platform string: 'cisco_xe', 'frr', 'srlinux', 'arista_eos', etc.
        """
        device_info = DEVICES.get(device, {})
        device_type = device_info.get("device_type", "").lower()

        if device_type in ("cisco_xe", "cisco_ios"):
            return "cisco_xe"
        elif "frr" in device_type or device_type == "containerlab_frr":
            return "frr"
        elif "srlinux" in device_type or device_type == "containerlab_srlinux":
            return "srlinux"
        elif "arista" in device_type or "eos" in device_type:
            return "arista_eos"
        else:
            # Default to cisco_xe for unknown types
            return "cisco_xe"

    def _is_containerlab_device(self, device: str) -> bool:
        """Check if device is a containerlab device (requires multipass access).

        Returns:
            True if device is containerlab, False otherwise
        """
        device_info = DEVICES.get(device, {})
        device_type = device_info.get("device_type", "").lower()
        return device_type.startswith("containerlab_") or "container" in device_info

    async def _get_readonly_connection(
        self, device: str
    ) -> Union[AsyncIOSXEDriver, AsyncGenericDriver]:
        """Create an async Scrapli connection using read-only credentials.

        IMPORTANT: This method uses READ-ONLY credentials, not admin credentials.
        The connection can only execute show commands.

        Args:
            device: Device name

        Returns:
            Appropriate async driver for the device platform

        Raises:
            ValueError: If device not found
        """
        if device not in DEVICES:
            raise ValueError(f"Device '{device}' not found in inventory")

        device_info = DEVICES[device]
        username, password = self._credentials.get_credentials()
        platform = self._get_device_platform(device)

        if platform == "frr":
            # FRR uses generic driver - commands wrapped with vtysh
            return AsyncGenericDriver(
                host=device_info["host"],
                auth_username=username,
                auth_password=password,
                auth_strict_key=SSH_STRICT_KEY,
                transport="asyncssh",
                timeout_socket=10,
                timeout_transport=10,
            )
        else:
            # Cisco IOS-XE (default)
            return AsyncIOSXEDriver(
                host=device_info["host"],
                auth_username=username,
                auth_password=password,
                auth_strict_key=SSH_STRICT_KEY,
                transport="asyncssh",
                timeout_socket=10,
                timeout_transport=10,
            )

    def _get_cached_data(self, device: str, source: str) -> Optional[CachedData]:
        """Get cached data for a device/source if it exists and is fresh enough.

        Args:
            device: Device name
            source: Data source name (interface, ospf, bgp, routing)

        Returns:
            CachedData if exists and not stale, None otherwise
        """
        max_age = self._config.get("data_max_age_sec", 300)
        device_cache = self._data_cache.get(device, {})
        cached = device_cache.get(source)

        if cached is None:
            return None

        if cached.status != "ok" or cached.age_sec > max_age:
            return None

        return cached

    def _cache_data(
        self, device: str, source: str, data: dict | list | str | None,
        status: str = "ok", error_message: Optional[str] = None
    ) -> CachedData:
        """Cache collected data for a device/source.

        Args:
            device: Device name
            source: Data source name
            data: Collected data
            status: "ok", "error", "missing"
            error_message: Error details if status != "ok"

        Returns:
            The cached data object
        """
        if device not in self._data_cache:
            self._data_cache[device] = {}

        cached = CachedData(
            data=data,
            collected_at=time.time(),
            status=status,
            error_message=error_message,
        )
        self._data_cache[device][source] = cached
        return cached

    def _wrap_command_for_platform(self, device: str, command: str) -> str:
        """Wrap a command for the device's platform.

        FRR requires commands to be wrapped with 'vtysh -c "..."'.
        Cisco commands are used as-is.

        Args:
            device: Device name
            command: The show command to run

        Returns:
            Platform-appropriate command string
        """
        platform = self._get_device_platform(device)

        if platform == "frr":
            # FRR: wrap with vtysh
            # Escape any quotes in the command
            escaped = command.replace('"', '\\"')
            return f'vtysh -c "{escaped}"'
        else:
            # Cisco and others: use command as-is
            return command

    def _get_platform_command(self, device: str, command_type: str, interface: str = "") -> str:
        """Get the platform-specific command for a data collection type.

        Args:
            device: Device name
            command_type: Type of command (interface, ospf, bgp, routing)
            interface: Interface name (for interface command)

        Returns:
            Platform-appropriate command string
        """
        platform = self._get_device_platform(device)

        if platform == "srlinux":
            # Nokia SR Linux commands
            commands = {
                "interface": f"show interface {interface} detail",
                "ospf": "show network-instance default protocols ospf neighbor",
                "bgp": "show network-instance default protocols bgp neighbor",
                "routing": "show network-instance default route-table ipv4-unicast route",
            }
        else:
            # Cisco IOS-XE and FRR use similar commands
            commands = {
                "interface": f"show interface {interface}",
                "ospf": "show ip ospf neighbor",
                "bgp": "show ip bgp summary",
                "routing": "show ip route",
            }

        return commands.get(command_type, "")

    async def _collect_interface_state(
        self, device: str, interface: str
    ) -> CachedData:
        """Collect interface state (up/down status and IP address).

        Uses: show interface <interface>

        Args:
            device: Device name
            interface: Interface name (normalized)

        Returns:
            CachedData with interface state dict:
            {
                "status": "up" | "down" | "administratively down",
                "ip_address": "10.0.12.1/30" | None,
                "line_protocol": "up" | "down",
            }
        """
        try:
            platform = self._get_device_platform(device)
            cmd = self._get_platform_command(device, "interface", interface)

            if self._is_containerlab_device(device):
                # Use containerlab module for multipass/docker exec
                output = await get_containerlab_command_output(device, cmd)
            else:
                # Use Scrapli for direct SSH
                conn = await self._get_readonly_connection(device)
                cmd = self._wrap_command_for_platform(device, cmd)
                async with conn:
                    response = await conn.send_command(cmd)
                    output = response.result

            # Parse interface status
            state = self._parse_interface_state(output, platform)
            return self._cache_data(device, f"interface:{interface}", state)

        except Exception as e:
            logger.error(f"Failed to collect interface state for {device}/{interface}: {e}")
            return self._cache_data(
                device, f"interface:{interface}", None,
                status="error", error_message=str(e)
            )

    def _parse_interface_state(self, output: str, platform: str = "cisco_xe") -> dict:
        """Parse 'show interface' output for status and IP.

        Args:
            output: Raw command output
            platform: Device platform (cisco_xe, frr, srlinux, etc.)

        Returns:
            Dict with status, ip_address, line_protocol
        """
        result = {
            "status": "unknown",
            "ip_address": None,
            "line_protocol": "unknown",
        }

        if platform == "srlinux":
            # SR Linux format:
            # ethernet-1/1 is down, reason lower-layer-down
            # OR: mgmt0 is up, speed 1G, type None
            # Oper state          : up (with variable spacing)
            # IPv4 addr    : 10.0.0.1/24

            # First check the brief format: "mgmt0 is up, speed 1G"
            status_match = re.search(
                r"^\S+ is (up|down)",
                output, re.MULTILINE
            )
            if status_match:
                result["status"] = status_match.group(1).lower()
                result["line_protocol"] = status_match.group(1).lower()

            # Also check "Oper state" line for detailed view (with flexible spacing)
            oper_match = re.search(r"Oper state\s+:\s*(up|down)", output, re.IGNORECASE)
            if oper_match:
                result["status"] = oper_match.group(1).lower()
                result["line_protocol"] = oper_match.group(1).lower()

            # SR Linux IPv4 address format (with flexible spacing)
            ip_match = re.search(r"IPv4 addr\s+:\s*(\d+\.\d+\.\d+\.\d+/\d+)", output)
            if ip_match:
                result["ip_address"] = ip_match.group(1)

        elif platform == "frr":
            # FRR format:
            # Interface eth1 is up, line protocol is up
            #   inet 10.0.13.2/30 broadcast 10.0.13.3
            status_match = re.search(
                r"Interface \S+ is (up|down|administratively down)",
                output, re.MULTILINE | re.IGNORECASE
            )
            if status_match:
                result["status"] = status_match.group(1).lower()
                result["line_protocol"] = "up" if "up" in status_match.group(1).lower() else "down"

            # FRR IP address format
            ip_match = re.search(r"inet (\d+\.\d+\.\d+\.\d+/\d+)", output)
            if ip_match:
                result["ip_address"] = ip_match.group(1)
        else:
            # Cisco IOS-XE format:
            # GigabitEthernet1 is up, line protocol is up
            # GigabitEthernet1 is administratively down, line protocol is down
            status_match = re.search(
                r"^\S+ is (up|down|administratively down), line protocol is (up|down)",
                output, re.MULTILINE
            )
            if status_match:
                result["status"] = status_match.group(1)
                result["line_protocol"] = status_match.group(2)

            # Cisco IP address format
            ip_match = re.search(r"Internet address is (\S+)", output)
            if ip_match:
                result["ip_address"] = ip_match.group(1)

        return result

    async def _collect_ospf_neighbors(self, device: str) -> CachedData:
        """Collect OSPF neighbor information.

        Uses: show ip ospf neighbor

        Args:
            device: Device name

        Returns:
            CachedData with list of OSPF neighbors:
            [
                {
                    "neighbor_id": "198.51.100.1",
                    "priority": 1,
                    "state": "FULL/DR",
                    "dead_time": "00:00:35",
                    "address": "10.0.12.1",
                    "interface": "GigabitEthernet1",
                },
                ...
            ]
        """
        try:
            platform = self._get_device_platform(device)
            cmd = self._get_platform_command(device, "ospf")

            if self._is_containerlab_device(device):
                # Use containerlab module for multipass/docker exec
                output = await get_containerlab_command_output(device, cmd)
            else:
                # Use Scrapli for direct SSH
                conn = await self._get_readonly_connection(device)
                cmd = self._wrap_command_for_platform(device, cmd)
                async with conn:
                    response = await conn.send_command(cmd)
                    output = response.result

            neighbors = self._parse_ospf_neighbors(output, platform)
            return self._cache_data(device, "ospf", neighbors)

        except Exception as e:
            logger.error(f"Failed to collect OSPF neighbors for {device}: {e}")
            return self._cache_data(
                device, "ospf", None,
                status="error", error_message=str(e)
            )

    def _parse_ospf_neighbors(self, output: str, platform: str = "cisco_xe") -> list[dict]:
        """Parse 'show ip ospf neighbor' output.

        Cisco IOS-XE example:
        Neighbor ID     Pri   State           Dead Time   Address         Interface
        198.51.100.1      1   FULL/DR         00:00:35    10.0.12.1       GigabitEthernet1
        198.51.100.2      1   FULL/BDR        00:00:33    10.0.24.2       GigabitEthernet2
        198.51.100.3      0   FULL/  -        00:00:39    10.0.13.2       GigabitEthernet2

        FRR example:
        Neighbor ID     Pri State           Up Time         Dead Time Address         Interface
        10.0.13.1         1 Full/DR         3h17m22s          39.123s 10.0.13.1       eth0:10.0.13.2

        SR Linux example (table format):
        +----------------+------------+-------+----------+-----------+----------------+
        | Neighbor       | State      | Pri   | DR       | BDR       | Interface      |
        +================+============+=======+==========+===========+================+
        | 10.0.0.1       | full       | 1     | 10.0.0.1 | 10.0.0.2  | ethernet-1/1.0 |
        +----------------+------------+-------+----------+-----------+----------------+

        Args:
            output: Raw command output
            platform: Device platform (cisco_xe, frr, srlinux, etc.)

        Returns:
            List of neighbor dicts
        """
        neighbors = []
        lines = output.strip().split('\n')

        if platform == "srlinux":
            # SR Linux uses table format with | delimiters
            for line in lines:
                # Skip header and separator lines
                if line.startswith('+') or line.startswith('|') and 'Neighbor' in line:
                    continue
                if '|' in line:
                    # Parse table row: | Neighbor | State | Pri | DR | BDR | Interface |
                    parts = [p.strip() for p in line.split('|') if p.strip()]
                    if len(parts) >= 6 and re.match(r'\d+\.\d+\.\d+\.\d+', parts[0]):
                        neighbors.append({
                            "neighbor_id": parts[0],
                            "priority": int(parts[2]) if parts[2].isdigit() else 1,
                            "state": f"FULL/{parts[3]}" if parts[1].lower() == "full" else parts[1].upper(),
                            "dead_time": "N/A",  # SR Linux doesn't show dead time in this format
                            "address": parts[3],  # DR address as neighbor address
                            "interface": parts[5],
                        })
        elif platform == "frr":
            # FRR format - different column order and time formats
            for line in lines:
                # FRR: Neighbor ID  Pri  State  Up Time  Dead Time  Address  Interface:IP
                match = re.match(
                    r'^(\d+\.\d+\.\d+\.\d+)\s+'   # Neighbor ID
                    r'(\d+)\s+'                    # Priority
                    r'(\S+/\S+)\s+'                # State (e.g., Full/DR)
                    r'(\S+)\s+'                    # Up Time (3h17m22s format)
                    r'(\S+)\s+'                    # Dead Time (39.123s format)
                    r'(\d+\.\d+\.\d+\.\d+)\s+'    # Address
                    r'(\S+)',                      # Interface (may include :IP)
                    line
                )
                if match:
                    # FRR interface may be "eth0:10.0.13.2" - extract just interface name
                    interface_raw = match.group(7)
                    interface_name = interface_raw.split(':')[0] if ':' in interface_raw else interface_raw
                    neighbors.append({
                        "neighbor_id": match.group(1),
                        "priority": int(match.group(2)),
                        "state": match.group(3),
                        "dead_time": match.group(5),  # FRR has different dead time format
                        "address": match.group(6),
                        "interface": interface_name,
                    })
        else:
            # Cisco IOS-XE format
            for line in lines:
                # Match OSPF neighbor lines (IP at start, then fields)
                # Neighbor ID format: x.x.x.x
                # State can be "FULL/DR", "FULL/BDR", or "FULL/  -" (with spaces)
                match = re.match(
                    r'^(\d+\.\d+\.\d+\.\d+)\s+'   # Neighbor ID
                    r'(\d+)\s+'                    # Priority
                    r'(\S+/\s*\S*)\s+'              # State (e.g., FULL/DR, FULL/  -)
                    r'(\d+:\d+:\d+)\s+'            # Dead Time (HH:MM:SS format)
                    r'(\d+\.\d+\.\d+\.\d+)\s+'    # Address
                    r'(\S+)',                      # Interface
                    line
                )
                if match:
                    neighbors.append({
                        "neighbor_id": match.group(1),
                        "priority": int(match.group(2)),
                        "state": match.group(3).strip(),
                        "dead_time": match.group(4),
                        "address": match.group(5),
                        "interface": match.group(6),
                    })

        return neighbors

    async def _collect_bgp_peers(self, device: str) -> CachedData:
        """Collect BGP peer information.

        Uses: show ip bgp summary

        Args:
            device: Device name

        Returns:
            CachedData with dict:
            {
                "configured": True/False,  # Whether BGP is running
                "local_as": 65000,
                "router_id": "198.51.100.1",
                "peers": [
                    {
                        "neighbor": "10.0.12.2",
                        "version": 4,
                        "remote_as": 65000,
                        "state": "Established" | "Idle" | ...,
                        "prefixes_received": 5,
                        "uptime": "01:23:45",
                    },
                    ...
                ]
            }
        """
        try:
            platform = self._get_device_platform(device)
            cmd = self._get_platform_command(device, "bgp")

            if self._is_containerlab_device(device):
                # Use containerlab module for multipass/docker exec
                output = await get_containerlab_command_output(device, cmd)
            else:
                # Use Scrapli for direct SSH
                conn = await self._get_readonly_connection(device)
                cmd = self._wrap_command_for_platform(device, cmd)
                async with conn:
                    response = await conn.send_command(cmd)
                    output = response.result

            bgp_data = self._parse_bgp_summary(output, platform)
            return self._cache_data(device, "bgp", bgp_data)

        except Exception as e:
            logger.error(f"Failed to collect BGP peers for {device}: {e}")
            return self._cache_data(
                device, "bgp", None,
                status="error", error_message=str(e)
            )

    def _parse_bgp_summary(self, output: str, platform: str = "cisco_xe") -> dict:
        """Parse 'show ip bgp summary' output.

        Cisco IOS-XE example:
        BGP router identifier 198.51.100.1, local AS number 65000
        ...
        Neighbor        V           AS MsgRcvd MsgSent   TblVer  InQ OutQ Up/Down  State/PfxRcd
        10.0.12.2       4        65000    1234    1234      100    0    0 01:23:45        5
        172.20.20.4     4        65100     456     789       50    0    0 00:45:00        3

        FRR example:
        IPv4 Unicast Summary (VRF default):
        BGP router identifier 172.20.20.4, local AS 65100
        ...
        Neighbor        V         AS   MsgRcvd   MsgSent   TblVer  InQ OutQ  Up/Down State/PfxRcd   PfxSnt
        10.0.13.1       4      65000       100       100        0    0    0 00:45:00            5        3

        Args:
            output: Raw command output
            platform: Device platform (cisco_xe, frr, etc.)

        Returns:
            Dict with configured flag, local_as, router_id, and peers list
        """
        result = {
            "configured": False,
            "local_as": None,
            "router_id": None,
            "peers": [],
        }

        # Check if BGP is configured
        if "% BGP not active" in output or "BGP not active" in output:
            return result

        # FRR also shows "No BGP neighbors" if none configured
        if "No BGP" in output and "neighbor" in output.lower():
            return result

        # SR Linux returns empty output if no BGP configured
        if platform == "srlinux" and not output.strip():
            return result

        if platform == "srlinux":
            # SR Linux format (table with | delimiters):
            # +----------------+---------------+-------+-------+------------+-----------+
            # | Peer           | Group         | State | AS    | Sent/Rcvd  | AFI/SAFI  |
            # +================+===============+=======+=======+============+===========+
            # | 10.0.0.1       | underlay      | estab | 65000 | 10/5       | ipv4-uni  |
            # +----------------+---------------+-------+-------+------------+-----------+
            result["configured"] = True  # If we have output, BGP is configured

            # Try to extract local AS from config context if available
            as_match = re.search(r"autonomous-system\s+(\d+)", output)
            if as_match:
                result["local_as"] = int(as_match.group(1))

            for line in output.strip().split('\n'):
                if '|' in line and not line.startswith('+'):
                    parts = [p.strip() for p in line.split('|') if p.strip()]
                    # Skip header row
                    if len(parts) >= 4 and parts[0] != 'Peer' and re.match(r'\d+\.\d+\.\d+\.\d+', parts[0]):
                        state_raw = parts[2].lower() if len(parts) > 2 else "unknown"
                        state = "Established" if state_raw in ("estab", "established") else state_raw.capitalize()

                        # Parse Sent/Rcvd field (e.g., "10/5")
                        prefixes = 0
                        if len(parts) > 4 and '/' in parts[4]:
                            try:
                                prefixes = int(parts[4].split('/')[1])
                            except (ValueError, IndexError):
                                pass

                        result["peers"].append({
                            "neighbor": parts[0],
                            "version": 4,
                            "remote_as": int(parts[3]) if parts[3].isdigit() else 0,
                            "uptime": "N/A",
                            "state": state,
                            "prefixes_received": prefixes,
                        })
        elif platform == "frr":
            # FRR format: BGP router identifier X.X.X.X, local AS 65100
            header_match = re.search(
                r"BGP router identifier (\d+\.\d+\.\d+\.\d+), local AS (\d+)",
                output
            )
            if header_match:
                result["configured"] = True
                result["router_id"] = header_match.group(1)
                result["local_as"] = int(header_match.group(2))

            # FRR neighbor format - similar to Cisco but may have extra PfxSnt column
            lines = output.strip().split('\n')
            for line in lines:
                match = re.match(
                    r'^(\d+\.\d+\.\d+\.\d+)\s+'  # Neighbor IP
                    r'(\d+)\s+'                   # Version
                    r'(\d+)\s+'                   # AS
                    r'\d+\s+'                     # MsgRcvd
                    r'\d+\s+'                     # MsgSent
                    r'\d+\s+'                     # TblVer
                    r'\d+\s+'                     # InQ
                    r'\d+\s+'                     # OutQ
                    r'(\S+)\s+'                   # Up/Down time
                    r'(\S+)',                     # State/PfxRcd
                    line
                )
                if match:
                    state_or_pfx = match.group(5)
                    if state_or_pfx.isdigit():
                        state = "Established"
                        prefixes = int(state_or_pfx)
                    else:
                        state = state_or_pfx
                        prefixes = 0

                    result["peers"].append({
                        "neighbor": match.group(1),
                        "version": int(match.group(2)),
                        "remote_as": int(match.group(3)),
                        "uptime": match.group(4),
                        "state": state,
                        "prefixes_received": prefixes,
                    })
        else:
            # Cisco IOS-XE format
            # Parse router ID and local AS
            # BGP router identifier 198.51.100.1, local AS number 65000
            header_match = re.search(
                r"BGP router identifier (\d+\.\d+\.\d+\.\d+), local AS number (\d+)",
                output
            )
            if header_match:
                result["configured"] = True
                result["router_id"] = header_match.group(1)
                result["local_as"] = int(header_match.group(2))

            # Parse neighbor lines
            # Format varies but generally: Neighbor V AS ... State/PfxRcd
            lines = output.strip().split('\n')
            for line in lines:
                # Match neighbor lines
                # Neighbor        V           AS MsgRcvd MsgSent   TblVer  InQ OutQ Up/Down  State/PfxRcd
                match = re.match(
                    r'^(\d+\.\d+\.\d+\.\d+)\s+'  # Neighbor IP
                    r'(\d+)\s+'                   # Version
                    r'(\d+)\s+'                   # AS
                    r'\d+\s+'                     # MsgRcvd
                    r'\d+\s+'                     # MsgSent
                    r'\d+\s+'                     # TblVer
                    r'\d+\s+'                     # InQ
                    r'\d+\s+'                     # OutQ
                    r'(\S+)\s+'                   # Up/Down time
                    r'(\S+)',                     # State/PfxRcd
                    line
                )
                if match:
                    state_or_pfx = match.group(5)
                    # If it's a number, peer is established with that many prefixes
                    # If it's a word (Idle, Active, Connect, etc.), it's the state
                    if state_or_pfx.isdigit():
                        state = "Established"
                        prefixes = int(state_or_pfx)
                    else:
                        state = state_or_pfx
                        prefixes = 0

                    result["peers"].append({
                        "neighbor": match.group(1),
                        "version": int(match.group(2)),
                        "remote_as": int(match.group(3)),
                        "uptime": match.group(4),
                        "state": state,
                        "prefixes_received": prefixes,
                    })

        return result

    async def _collect_routing_table(self, device: str) -> CachedData:
        """Collect routing table information.

        Uses: show ip route

        Args:
            device: Device name

        Returns:
            CachedData with list of routes:
            [
                {
                    "prefix": "10.0.12.0/30",
                    "type": "C",  # C=connected, O=OSPF, B=BGP, S=static
                    "protocol": "connected",
                    "next_hop": None,  # None for connected
                    "interface": "GigabitEthernet1",
                    "metric": 0,
                    "admin_distance": 0,
                },
                ...
            ]
        """
        try:
            platform = self._get_device_platform(device)
            cmd = self._get_platform_command(device, "routing")

            if self._is_containerlab_device(device):
                # Use containerlab module for multipass/docker exec
                output = await get_containerlab_command_output(device, cmd)
            else:
                # Use Scrapli for direct SSH
                conn = await self._get_readonly_connection(device)
                cmd = self._wrap_command_for_platform(device, cmd)
                async with conn:
                    response = await conn.send_command(cmd)
                    output = response.result

            routes = self._parse_routing_table(output, platform)
            return self._cache_data(device, "routing", routes)

        except Exception as e:
            logger.error(f"Failed to collect routing table for {device}: {e}")
            return self._cache_data(
                device, "routing", None,
                status="error", error_message=str(e)
            )

    def _parse_routing_table(self, output: str, platform: str = "cisco_xe") -> list[dict]:
        """Parse 'show ip route' output.

        Cisco IOS-XE example:
        C        10.0.12.0/30 is directly connected, GigabitEthernet1
        L        10.0.12.1/32 is directly connected, GigabitEthernet1
        O        10.0.13.0/30 [110/2] via 10.0.12.2, 01:23:45, GigabitEthernet1
        B        172.16.0.0/24 [20/0] via 10.0.12.2, 00:45:00

        FRR example:
        Codes: K - kernel route, C - connected, S - static, R - RIP,
               O - OSPF, I - IS-IS, B - BGP, E - EIGRP, N - NHRP,
        C>* 10.0.13.0/30 is directly connected, eth0, 3d22h34m
        O>* 10.0.12.0/30 [110/20] via 10.0.13.1, eth0, 01:23:45
        B>* 172.16.0.0/24 [20/0] via 10.0.13.1, eth0, 00:45:00

        Args:
            output: Raw command output
            platform: Device platform (cisco_xe, frr, etc.)

        Returns:
            List of route dicts
        """
        routes = []
        protocol_map = {
            "C": "connected",
            "L": "local",
            "S": "static",
            "O": "ospf",
            "O IA": "ospf",
            "O N1": "ospf",
            "O N2": "ospf",
            "O E1": "ospf",
            "O E2": "ospf",
            "B": "bgp",
            "D": "eigrp",
            "D EX": "eigrp",
            "i": "isis",
            "I": "isis",
            "R": "rip",
            "K": "kernel",
            "N": "nhrp",
        }

        lines = output.strip().split('\n')

        if platform == "srlinux":
            # SR Linux format (table with | delimiters):
            # +------------------+-----------+-------+----------+----------+----------------+
            # | Prefix           | Type      | Proto | Pref     | Metric   | Next-hop       |
            # +==================+===========+=======+==========+==========+================+
            # | 10.0.0.0/24      | local     | local | 0        | 0        | ethernet-1/1.0 |
            # | 10.0.1.0/24      | remote    | ospf  | 10       | 20       | 10.0.0.2       |
            # +------------------+-----------+-------+----------+----------+----------------+
            srlinux_proto_map = {
                "local": "connected",
                "host": "local",
                "static": "static",
                "ospf": "ospf",
                "bgp": "bgp",
                "isis": "isis",
            }

            for line in lines:
                if '|' in line and not line.startswith('+'):
                    parts = [p.strip() for p in line.split('|') if p.strip()]
                    # Skip header row
                    if len(parts) >= 6 and parts[0] != 'Prefix' and '/' in parts[0]:
                        proto = parts[2].lower() if len(parts) > 2 else "unknown"
                        route_type = proto[0].upper() if proto else "?"

                        routes.append({
                            "prefix": parts[0],
                            "type": route_type,
                            "protocol": srlinux_proto_map.get(proto, proto),
                            "next_hop": parts[5] if len(parts) > 5 and not parts[5].startswith("ethernet") else None,
                            "interface": parts[5] if len(parts) > 5 and parts[5].startswith("ethernet") else None,
                            "admin_distance": int(parts[3]) if parts[3].isdigit() else 0,
                            "metric": int(parts[4]) if parts[4].isdigit() else 0,
                        })
        elif platform == "frr":
            # FRR format uses C>*, O>*, B>*, etc.
            for line in lines:
                # FRR connected: C>* 10.0.13.0/30 is directly connected, eth0, 3d22h34m
                frr_connected_match = re.match(
                    r'^([CSKORNBI])>\*\s+'        # Protocol code with >*
                    r'(\d+\.\d+\.\d+\.\d+/\d+)\s+'
                    r'is directly connected,\s+'
                    r'(\S+)',                      # Interface
                    line
                )
                if frr_connected_match:
                    route_type = frr_connected_match.group(1)
                    routes.append({
                        "prefix": frr_connected_match.group(2),
                        "type": route_type,
                        "protocol": protocol_map.get(route_type, "connected"),
                        "next_hop": None,
                        "interface": frr_connected_match.group(3).rstrip(','),
                        "metric": 0,
                        "admin_distance": 0,
                    })
                    continue

                # FRR with next-hop: O>* 10.0.12.0/30 [110/20] via 10.0.13.1, eth0, 01:23:45
                frr_via_match = re.match(
                    r'^([CSKORNBI])>\*\s+'         # Protocol code with >*
                    r'(\d+\.\d+\.\d+\.\d+/\d+)\s+'
                    r'\[(\d+)/(\d+)\]\s+'          # [AD/metric]
                    r'via\s+(\d+\.\d+\.\d+\.\d+)'  # Next-hop
                    r'(?:,\s+(\S+))?',             # Optional interface
                    line
                )
                if frr_via_match:
                    route_type = frr_via_match.group(1)
                    interface = frr_via_match.group(6)
                    if interface:
                        interface = interface.rstrip(',')
                    routes.append({
                        "prefix": frr_via_match.group(2),
                        "type": route_type,
                        "protocol": protocol_map.get(route_type, route_type.lower()),
                        "next_hop": frr_via_match.group(5),
                        "interface": interface,
                        "admin_distance": int(frr_via_match.group(3)),
                        "metric": int(frr_via_match.group(4)),
                    })
        else:
            # Cisco IOS-XE format
            for line in lines:
                # Connected routes: C 10.0.12.0/30 is directly connected, GigabitEthernet1
                connected_match = re.match(
                    r'^([CL])\s+'
                    r'(\d+\.\d+\.\d+\.\d+/\d+)\s+'
                    r'is directly connected,\s+'
                    r'(\S+)',
                    line
                )
                if connected_match:
                    route_type = connected_match.group(1)
                    routes.append({
                        "prefix": connected_match.group(2),
                        "type": route_type,
                        "protocol": protocol_map.get(route_type, "connected"),
                        "next_hop": None,
                        "interface": connected_match.group(3),
                        "metric": 0,
                        "admin_distance": 0 if route_type == "C" else 0,
                    })
                    continue

                # Routes with next-hop: O 10.0.13.0/30 [110/2] via 10.0.12.2, ...
                via_match = re.match(
                    r'^([OSBDRI](?:\s+\S+)?)\s+'  # Protocol code (may have qualifier like O IA)
                    r'(\d+\.\d+\.\d+\.\d+/\d+)\s+'
                    r'\[(\d+)/(\d+)\]\s+'          # [AD/metric]
                    r'via\s+(\d+\.\d+\.\d+\.\d+)'  # Next-hop
                    r'(?:,\s+\S+)?'                # Optional uptime
                    r'(?:,\s+(\S+))?',             # Optional interface
                    line
                )
                if via_match:
                    route_type = via_match.group(1).strip()
                    routes.append({
                        "prefix": via_match.group(2),
                        "type": route_type,
                        "protocol": protocol_map.get(route_type, route_type.lower()),
                        "next_hop": via_match.group(5),
                        "interface": via_match.group(6) if via_match.group(6) else None,
                        "admin_distance": int(via_match.group(3)),
                        "metric": int(via_match.group(4)),
                    })

        return routes

    async def _collect_all_data(
        self, device: str, interface: str, refresh: bool = False
    ) -> dict[str, CachedData]:
        """Collect all required data for impact analysis.

        Collects interface state, OSPF neighbors, BGP peers, and routing table
        in parallel for efficiency.

        Args:
            device: Device name
            interface: Interface name (normalized)
            refresh: Force refresh even if cached data exists

        Returns:
            Dict of source_name -> CachedData
        """
        results = {}
        interface_key = f"interface:{interface}"

        # Check cache first if not refreshing
        if not refresh:
            cached_interface = self._get_cached_data(device, interface_key)
            cached_ospf = self._get_cached_data(device, "ospf")
            cached_bgp = self._get_cached_data(device, "bgp")
            cached_routing = self._get_cached_data(device, "routing")

            # If all data is cached and fresh, return it
            if all([cached_interface, cached_ospf, cached_bgp, cached_routing]):
                return {
                    interface_key: cached_interface,
                    "ospf": cached_ospf,
                    "bgp": cached_bgp,
                    "routing": cached_routing,
                }

        # Collect data in parallel using asyncio.gather
        # Use a lock to prevent concurrent refreshes to the same device
        lock = self._get_device_lock(device)
        async with lock:
            try:
                timeout = self._config.get("analysis_timeout_sec", 10)
                interface_task = self._collect_interface_state(device, interface)
                ospf_task = self._collect_ospf_neighbors(device)
                bgp_task = self._collect_bgp_peers(device)
                routing_task = self._collect_routing_table(device)

                collected = await asyncio.wait_for(
                    asyncio.gather(
                        interface_task, ospf_task, bgp_task, routing_task,
                        return_exceptions=True
                    ),
                    timeout=timeout
                )

                results[interface_key] = (
                    collected[0] if not isinstance(collected[0], Exception)
                    else self._cache_data(device, interface_key, None, "error", str(collected[0]))
                )
                results["ospf"] = (
                    collected[1] if not isinstance(collected[1], Exception)
                    else self._cache_data(device, "ospf", None, "error", str(collected[1]))
                )
                results["bgp"] = (
                    collected[2] if not isinstance(collected[2], Exception)
                    else self._cache_data(device, "bgp", None, "error", str(collected[2]))
                )
                results["routing"] = (
                    collected[3] if not isinstance(collected[3], Exception)
                    else self._cache_data(device, "routing", None, "error", str(collected[3]))
                )

            except asyncio.TimeoutError:
                logger.error(f"Timeout collecting data from {device}")
                # Return partial results as errors
                for source in [interface_key, "ospf", "bgp", "routing"]:
                    if source not in results:
                        results[source] = self._cache_data(
                            device, source, None,
                            status="error", error_message="Collection timeout"
                        )

        return results

    # =========================================================================
    # Impact Detection Methods (Phase 1d)
    # =========================================================================

    def _find_ospf_adjacencies_on_interface(
        self, interface: str, ospf_data: CachedData
    ) -> list[OSPFAdjacency]:
        """Find OSPF neighbors that would be lost if interface is shutdown.

        Matches neighbors where the interface field matches the target interface.

        Args:
            interface: Normalized interface name
            ospf_data: Cached OSPF neighbor data

        Returns:
            List of OSPFAdjacency objects that would be lost
        """
        adjacencies = []

        if ospf_data.status != "ok" or not ospf_data.data:
            return adjacencies

        neighbors = ospf_data.data
        if not isinstance(neighbors, list):
            return adjacencies

        for neighbor in neighbors:
            neighbor_interface = neighbor.get("interface", "")
            # Match interface name (case-insensitive)
            if neighbor_interface.lower() == interface.lower():
                adjacencies.append(OSPFAdjacency(
                    neighbor_ip=neighbor.get("address", ""),
                    neighbor_router_id=neighbor.get("neighbor_id", ""),
                    neighbor_device=self._lookup_device_by_ip(neighbor.get("address")),
                    area=self._extract_ospf_area(neighbor.get("state", "")),
                ))

        return adjacencies

    def _extract_ospf_area(self, state: str) -> str:
        """Extract area from OSPF state string or return default.

        The state field contains FULL/DR or similar, not the area.
        For now, return "0" as we don't have area info in neighbor output.
        """
        # OSPF area is not in the neighbor output - would need show ip ospf interface
        # For Phase 1, return "unknown" - Phase 2 could add area detection
        return "0"

    def _lookup_device_by_ip(self, ip: str) -> Optional[str]:
        """Look up device name by IP address.

        Args:
            ip: IP address to look up

        Returns:
            Device name if found, None otherwise
        """
        if not ip:
            return None

        # Search through DEVICES for matching management IP
        for device_name, device_info in DEVICES.items():
            if device_info.get("host") == ip:
                return device_name

        # Could also check interface IPs if we had that data cached
        return None

    def _find_bgp_peers_on_interface(
        self, interface: str, interface_ip: Optional[str], bgp_data: CachedData
    ) -> list[BGPPeer]:
        """Find BGP peers that would be lost if interface is shutdown.

        BGP sessions are affected if the peer address is reachable via
        the target interface (i.e., peer IP is in the same subnet as
        the interface IP).

        Args:
            interface: Normalized interface name
            interface_ip: IP address of the interface (e.g., "10.0.12.1/30")
            bgp_data: Cached BGP summary data

        Returns:
            List of BGPPeer objects that would be lost
        """
        peers_lost = []

        if bgp_data.status != "ok" or not bgp_data.data:
            return peers_lost

        bgp_info = bgp_data.data
        if not isinstance(bgp_info, dict):
            return peers_lost

        # BGP not configured - no peers to lose
        if not bgp_info.get("configured", False):
            return peers_lost

        # If we don't know the interface IP, we can't determine which peers
        # are reachable via this interface
        if not interface_ip:
            return peers_lost

        # Parse interface IP and mask
        try:
            if "/" in interface_ip:
                ip_part, prefix_len = interface_ip.split("/")
                prefix_len = int(prefix_len)
            else:
                ip_part = interface_ip
                prefix_len = 32
        except (ValueError, AttributeError):
            return peers_lost

        # Check each peer to see if it's in the same subnet
        for peer in bgp_info.get("peers", []):
            peer_ip = peer.get("neighbor", "")
            if self._is_ip_in_subnet(peer_ip, ip_part, prefix_len):
                peers_lost.append(BGPPeer(
                    peer_ip=peer_ip,
                    peer_asn=peer.get("remote_as", 0),
                    peer_device=self._lookup_device_by_ip(peer_ip),
                ))

        return peers_lost

    def _is_ip_in_subnet(self, ip: str, network_ip: str, prefix_len: int) -> bool:
        """Check if an IP address is in a subnet.

        Args:
            ip: IP to check
            network_ip: Network/interface IP
            prefix_len: Prefix length (e.g., 30 for /30)

        Returns:
            True if ip is in the same subnet
        """
        try:
            # Convert IPs to integers
            def ip_to_int(ip_str: str) -> int:
                parts = ip_str.split(".")
                return (int(parts[0]) << 24) + (int(parts[1]) << 16) + \
                       (int(parts[2]) << 8) + int(parts[3])

            ip_int = ip_to_int(ip)
            network_int = ip_to_int(network_ip)

            # Create mask from prefix length
            mask = (0xFFFFFFFF << (32 - prefix_len)) & 0xFFFFFFFF

            # Check if both IPs are in the same network
            return (ip_int & mask) == (network_int & mask)

        except (ValueError, IndexError, AttributeError):
            return False

    def _find_affected_routes(
        self, interface: str, routing_data: CachedData
    ) -> list[AffectedRoute]:
        """Find routes that would be removed if interface is shutdown.

        Connected routes on the interface will be removed. Other routes
        using the interface as next-hop or outgoing interface will also
        be affected.

        Args:
            interface: Normalized interface name
            routing_data: Cached routing table data

        Returns:
            List of AffectedRoute objects (without alternate_exists set yet)
        """
        affected = []

        if routing_data.status != "ok" or not routing_data.data:
            return affected

        routes = routing_data.data
        if not isinstance(routes, list):
            return affected

        for route in routes:
            route_interface = route.get("interface", "")
            route_type = route.get("type", "")
            prefix = route.get("prefix", "")
            protocol = route.get("protocol", "")

            # Skip local routes (/32 interface addresses)
            if route_type == "L":
                continue

            # Check if route uses this interface
            if route_interface and route_interface.lower() == interface.lower():
                affected.append(AffectedRoute(
                    prefix=prefix,
                    route_type=protocol,
                    alternate_exists=False,  # Will be updated by _check_alternate_routes
                ))

        return affected

    def _check_alternate_routes(
        self, affected_routes: list[AffectedRoute], routing_data: CachedData,
        interface: str
    ) -> list[AffectedRoute]:
        """Check if alternate routes exist for affected prefixes.

        For each affected route, check if another route to the same
        prefix exists via a different interface.

        Args:
            affected_routes: List of routes that would be removed
            routing_data: Full routing table
            interface: Interface being shutdown

        Returns:
            Updated list with alternate_exists flag set
        """
        if routing_data.status != "ok" or not routing_data.data:
            return affected_routes

        routes = routing_data.data
        if not isinstance(routes, list):
            return affected_routes

        # Build a map of prefix -> list of interfaces
        prefix_interfaces: dict[str, list[str]] = {}
        for route in routes:
            prefix = route.get("prefix", "")
            route_interface = route.get("interface", "")
            route_type = route.get("type", "")

            # Skip local routes
            if route_type == "L":
                continue

            if prefix not in prefix_interfaces:
                prefix_interfaces[prefix] = []
            if route_interface:
                prefix_interfaces[prefix].append(route_interface.lower())

        # Update affected routes with alternate_exists
        updated = []
        for route in affected_routes:
            interfaces_for_prefix = prefix_interfaces.get(route.prefix, [])

            # Remove the interface being shutdown from the list
            other_interfaces = [
                iface for iface in interfaces_for_prefix
                if iface != interface.lower()
            ]

            # If there are other interfaces, an alternate exists
            updated.append(AffectedRoute(
                prefix=route.prefix,
                route_type=route.route_type,
                alternate_exists=len(other_interfaces) > 0,
            ))

        return updated

    def _build_impact(
        self, ospf_adjacencies: list[OSPFAdjacency],
        bgp_peers: list[BGPPeer],
        affected_routes: list[AffectedRoute]
    ) -> Impact:
        """Build Impact object with summary counts.

        Args:
            ospf_adjacencies: OSPF neighbors that would be lost
            bgp_peers: BGP peers that would be lost
            affected_routes: Routes that would be removed

        Returns:
            Impact object with all data and summary
        """
        routes_with_alt = sum(1 for r in affected_routes if r.alternate_exists)
        routes_without_alt = len(affected_routes) - routes_with_alt

        return Impact(
            ospf_adjacencies_lost=ospf_adjacencies,
            bgp_peers_lost=bgp_peers,
            routes_removed=affected_routes,
            summary=ImpactSummary(
                adjacencies_affected=len(ospf_adjacencies) + len(bgp_peers),
                routes_affected=len(affected_routes),
                routes_with_alternate=routes_with_alt,
                routes_without_alternate=routes_without_alt,
            ),
        )

    # =========================================================================
    # Main Analysis Method (Phase 1c + 1d)
    # =========================================================================

    async def analyze(
        self,
        device: str,
        interface: str,
        command: str,
        refresh_data: bool = False,
        user: str = "anonymous",
    ) -> AnalysisResult:
        """Analyze impact of interface shutdown.

        Args:
            device: Device name
            interface: Interface name
            command: Command (must be "shutdown")
            refresh_data: Force data refresh
            user: User identifier for rate limiting

        Returns:
            AnalysisResult with impact details or error status
        """
        start_time = time.time()
        analysis_id = f"ia-{int(start_time * 1000) % 1000000:06d}"

        # Check if feature is enabled
        if not self._config.get("enabled", False):
            return AnalysisResult(
                status=AnalysisStatus.UNSUPPORTED,
                reason="Impact analysis feature is disabled",
                supported_in=None,
            )

        # Phase 1b: Validation (fast path, no data collection)
        platform_error = self._validate_platform(device)
        if platform_error:
            return platform_error

        interface_error = self._validate_interface(device, interface)
        if interface_error:
            return interface_error

        command_error = self._validate_command(command)
        if command_error:
            return command_error

        # Rate limiting for refresh requests
        if refresh_data:
            if self._is_refresh_in_progress(device):
                return AnalysisResult(
                    status=AnalysisStatus.REFRESH_IN_PROGRESS,
                    reason=f"Another refresh for {device} is currently in progress",
                    retry_after_sec=5,
                )

            if self._is_user_rate_limited(user):
                return AnalysisResult(
                    status=AnalysisStatus.RATE_LIMITED,
                    reason="User refresh limit exceeded (10/minute)",
                    retry_after_sec=60,
                )

            if self._is_device_rate_limited(device):
                return AnalysisResult(
                    status=AnalysisStatus.RATE_LIMITED,
                    reason=f"Device {device} refresh limit exceeded (2/minute)",
                    retry_after_sec=30,
                )

            # Record requests
            self._record_user_request(user)
            self._record_device_request(device)

        # Normalize interface name
        normalized_interface = self._normalize_interface_name(interface)

        # Phase 1c: Data collection
        try:
            collected_data = await self._collect_all_data(
                device, normalized_interface, refresh=refresh_data
            )
        except asyncio.TimeoutError:
            return AnalysisResult(
                status=AnalysisStatus.TIMEOUT,
                reason=f"Analysis timed out after {self._config.get('analysis_timeout_sec', 10)} seconds",
                suggestion="Try again with refresh_data=false to use cached data",
            )

        # Convert to DataSource dict for quality check
        interface_key = f"interface:{normalized_interface}"
        sources = {
            "interface": collected_data[interface_key].to_data_source(),
            "ospf": collected_data["ospf"].to_data_source(),
            "bgp": collected_data["bgp"].to_data_source(),
            "routing": collected_data["routing"].to_data_source(),
        }

        # Check data quality
        data_quality, refuse_result = self._build_data_quality(sources)
        if refuse_result:
            return refuse_result

        # Check if interface is already down (no impact)
        interface_data = collected_data[interface_key].data
        if interface_data and interface_data.get("status") in ["down", "administratively down"]:
            duration_ms = int((time.time() - start_time) * 1000)
            return AnalysisResult(
                status=AnalysisStatus.NO_IMPACT,
                analysis_id=analysis_id,
                device=device,
                interface=normalized_interface,
                command=command,
                current_state=InterfaceState(
                    interface_status=interface_data.get("status", "unknown"),
                    ip_address=interface_data.get("ip_address"),
                ),
                reason="Interface is already down - shutdown command has no additional impact",
                analysis_duration_ms=duration_ms,
            )

        # Build current state
        current_state = InterfaceState(
            interface_status=interface_data.get("status", "unknown") if interface_data else "unknown",
            ip_address=interface_data.get("ip_address") if interface_data else None,
        )

        # Phase 1d: Impact detection
        # Find OSPF adjacencies that would be lost
        ospf_adjacencies = self._find_ospf_adjacencies_on_interface(
            normalized_interface, collected_data["ospf"]
        )

        # Find BGP peers that would be lost
        bgp_peers = self._find_bgp_peers_on_interface(
            normalized_interface,
            interface_data.get("ip_address") if interface_data else None,
            collected_data["bgp"]
        )

        # Find routes that would be removed
        affected_routes = self._find_affected_routes(
            normalized_interface, collected_data["routing"]
        )

        # Check for alternate routes
        affected_routes = self._check_alternate_routes(
            affected_routes, collected_data["routing"], normalized_interface
        )

        # Build impact summary
        impact = self._build_impact(ospf_adjacencies, bgp_peers, affected_routes)

        # Categorize risk
        risk_category = self._categorize_risk(impact)

        # Build warnings
        warnings = []
        if impact.summary.routes_without_alternate > 0:
            warnings.append(
                f"WARNING: {impact.summary.routes_without_alternate} route(s) have no alternate path"
            )
        if len(ospf_adjacencies) > 0:
            warnings.append(
                f"OSPF: {len(ospf_adjacencies)} neighbor adjacency(ies) will be lost"
            )
        if len(bgp_peers) > 0:
            warnings.append(
                f"BGP: {len(bgp_peers)} peer session(s) will be lost"
            )

        duration_ms = int((time.time() - start_time) * 1000)

        return AnalysisResult(
            status=AnalysisStatus.COMPLETED,
            analysis_id=analysis_id,
            device=device,
            interface=normalized_interface,
            command=command,
            current_state=current_state,
            risk_category=risk_category,
            impact=impact,
            data_quality=data_quality,
            warnings=warnings,
            analysis_duration_ms=duration_ms,
        )

    def analyze_sync(
        self,
        device: str,
        interface: str,
        command: str,
        refresh_data: bool = False,
        user: str = "anonymous",
    ) -> AnalysisResult:
        """Synchronous wrapper for analyze().

        Args:
            device: Device name
            interface: Interface name
            command: Command (must be "shutdown")
            refresh_data: Force data refresh
            user: User identifier for rate limiting

        Returns:
            AnalysisResult with impact details or error status
        """
        try:
            loop = asyncio.get_event_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)

        return loop.run_until_complete(
            self.analyze(device, interface, command, refresh_data, user)
        )


# =============================================================================
# Module-level convenience functions
# =============================================================================

_analyzer: Optional[ImpactAnalyzer] = None


def get_analyzer() -> ImpactAnalyzer:
    """Get or create the ImpactAnalyzer singleton.

    Returns:
        ImpactAnalyzer instance
    """
    global _analyzer
    if _analyzer is None:
        _analyzer = ImpactAnalyzer()
    return _analyzer


async def analyze_impact(
    device: str,
    interface: str,
    command: str = "shutdown",
    refresh_data: bool = False,
    user: str = "anonymous",
) -> AnalysisResult:
    """Convenience function to analyze impact.

    Args:
        device: Device name
        interface: Interface name
        command: Command (must be "shutdown")
        refresh_data: Force data refresh
        user: User identifier for rate limiting

    Returns:
        AnalysisResult with impact details or error status
    """
    return await get_analyzer().analyze(device, interface, command, refresh_data, user)


def analyze_impact_sync(
    device: str,
    interface: str,
    command: str = "shutdown",
    refresh_data: bool = False,
    user: str = "anonymous",
) -> AnalysisResult:
    """Synchronous convenience function to analyze impact.

    Args:
        device: Device name
        interface: Interface name
        command: Command (must be "shutdown")
        refresh_data: Force data refresh
        user: User identifier for rate limiting

    Returns:
        AnalysisResult with impact details or error status
    """
    return get_analyzer().analyze_sync(device, interface, command, refresh_data, user)
