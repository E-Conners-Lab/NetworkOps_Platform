"""
Configuration Compliance Engine for NetworkOps.

Advanced compliance checking with section-based golden config comparison,
weighted scoring, remediation generation, and historical tracking.

Features:
- Section-based config parsing (not just line-by-line)
- Multiple golden templates per device role
- Weighted compliance scoring by section criticality
- Auto-generated remediation commands
- Compliance history tracking in SQLite
- Drift detection between checks

Usage:
    from core.compliance_engine import ComplianceEngine

    engine = ComplianceEngine()

    # Check single device
    result = await engine.check_compliance("R1")

    # Check all devices
    results = await engine.check_all_devices()

    # Get compliance history
    history = engine.get_compliance_history("R1", days=30)
"""

import asyncio
import json
import logging
import os
import re
import sqlite3
from dataclasses import dataclass, field, asdict
from datetime import timedelta

from core.timestamps import isonow, now
from enum import Enum
from pathlib import Path
from typing import Optional, Callable

logger = logging.getLogger(__name__)

# =============================================================================
# Configuration
# =============================================================================

TEMPLATES_DIR = Path(__file__).parent.parent / "data" / "compliance_templates"
COMPLIANCE_DB = Path(__file__).parent.parent / "data" / "compliance.db"

# Import UnifiedDB for centralized database access
from core.unified_db import UnifiedDB

# Section weights for scoring (higher = more critical)
DEFAULT_SECTION_WEIGHTS = {
    "aaa": 10,
    "logging": 8,
    "snmp": 7,
    "ntp": 6,
    "access-list": 9,
    "line vty": 8,
    "line con": 7,
    "banner": 5,
    "service": 6,
    "ip domain": 4,
    "crypto": 9,
    "interface": 5,
    "router": 6,
}


# =============================================================================
# Data Models
# =============================================================================

class ComplianceStatus(str, Enum):
    COMPLIANT = "compliant"
    NON_COMPLIANT = "non_compliant"
    PARTIAL = "partial"
    ERROR = "error"
    UNKNOWN = "unknown"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class ConfigSection:
    """A parsed configuration section."""
    name: str
    lines: list[str]
    start_line: int
    end_line: int

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "lines": self.lines,
            "start_line": self.start_line,
            "end_line": self.end_line,
        }


@dataclass
class ComplianceViolation:
    """A single compliance violation."""
    section: str
    rule_id: str
    rule_name: str
    severity: Severity
    expected: str
    actual: str
    remediation: str
    weight: int = 1

    def to_dict(self) -> dict:
        return {
            "section": self.section,
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "severity": self.severity.value,
            "expected": self.expected,
            "actual": self.actual,
            "remediation": self.remediation,
            "weight": self.weight,
        }


@dataclass
class ComplianceResult:
    """Result of a compliance check."""
    device: str
    template: str
    status: ComplianceStatus
    score: float  # 0-100
    checked_at: str
    total_rules: int
    passed_rules: int
    failed_rules: int
    violations: list[ComplianceViolation] = field(default_factory=list)
    remediation_commands: list[str] = field(default_factory=list)
    sections_checked: list[str] = field(default_factory=list)
    error: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "device": self.device,
            "template": self.template,
            "status": self.status.value,
            "score": round(self.score, 1),
            "checked_at": self.checked_at,
            "total_rules": self.total_rules,
            "passed_rules": self.passed_rules,
            "failed_rules": self.failed_rules,
            "violations": [v.to_dict() for v in self.violations],
            "remediation_commands": self.remediation_commands,
            "sections_checked": self.sections_checked,
            "error": self.error,
        }


@dataclass
class ComplianceRule:
    """A compliance rule definition."""
    id: str
    name: str
    description: str
    section: str
    severity: Severity
    match_type: str  # "present", "absent", "regex", "exact"
    pattern: str
    remediation_template: str
    weight: int = 1
    enabled: bool = True

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ComplianceTemplate:
    """A compliance template with rules."""
    name: str
    description: str
    device_roles: list[str]  # e.g., ["router", "switch", "firewall"]
    platform: str  # e.g., "cisco_ios", "cisco_nxos", "arista_eos"
    rules: list[ComplianceRule]
    version: str = "1.0"

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "description": self.description,
            "device_roles": self.device_roles,
            "platform": self.platform,
            "rules": [r.to_dict() for r in self.rules],
            "version": self.version,
        }


# =============================================================================
# Config Parser
# =============================================================================

class ConfigParser:
    """Parse network device configurations into sections."""

    # Section start patterns for different platforms
    SECTION_PATTERNS = {
        "cisco_ios": [
            (r"^interface\s+\S+", "interface"),
            (r"^router\s+\S+", "router"),
            (r"^ip access-list\s+\S+", "access-list"),
            (r"^line\s+\S+", "line"),
            (r"^aaa\s+", "aaa"),
            (r"^logging\s+", "logging"),
            (r"^snmp-server\s+", "snmp"),
            (r"^ntp\s+", "ntp"),
            (r"^crypto\s+", "crypto"),
            (r"^banner\s+\S+", "banner"),
            (r"^ip domain", "ip domain"),
            (r"^service\s+", "service"),
        ],
        "frr": [
            (r"^router\s+\S+", "router"),
            (r"^interface\s+\S+", "interface"),
            (r"^ip prefix-list\s+\S+", "prefix-list"),
            (r"^route-map\s+\S+", "route-map"),
            (r"^access-list\s+", "access-list"),
        ],
        "srlinux": [
            (r"^/interface\s+", "interface"),
            (r"^/network-instance\s+", "network-instance"),
            (r"^/routing-policy\s+", "routing-policy"),
            (r"^/system\s+", "system"),
        ],
    }

    # Map device_type to parser platform
    PLATFORM_MAP = {
        "cisco_xe": "cisco_ios",
        "cisco_ios": "cisco_ios",
        "containerlab_frr": "frr",
        "containerlab_srlinux": "srlinux",
    }

    @classmethod
    def parse(cls, config: str, platform: str = "cisco_ios") -> list[ConfigSection]:
        """Parse configuration into sections."""
        sections = []
        lines = config.split("\n")
        patterns = cls.SECTION_PATTERNS.get(platform, cls.SECTION_PATTERNS["cisco_ios"])

        current_section = None
        current_lines = []
        current_start = 0

        for i, line in enumerate(lines):
            stripped = line.strip()
            if not stripped or stripped.startswith("!"):
                continue

            # Check if this line starts a new section
            new_section = None
            for pattern, section_name in patterns:
                if re.match(pattern, stripped, re.IGNORECASE):
                    new_section = section_name
                    break

            if new_section:
                # Save previous section
                if current_section and current_lines:
                    sections.append(ConfigSection(
                        name=current_section,
                        lines=current_lines,
                        start_line=current_start,
                        end_line=i - 1,
                    ))

                current_section = new_section
                current_lines = [stripped]
                current_start = i
            elif current_section:
                # Continue current section (indented lines belong to section)
                if line.startswith(" ") or line.startswith("\t"):
                    current_lines.append(stripped)
                else:
                    # Non-indented line ends section
                    if current_lines:
                        sections.append(ConfigSection(
                            name=current_section,
                            lines=current_lines,
                            start_line=current_start,
                            end_line=i - 1,
                        ))
                    current_section = None
                    current_lines = []

        # Save final section
        if current_section and current_lines:
            sections.append(ConfigSection(
                name=current_section,
                lines=current_lines,
                start_line=current_start,
                end_line=len(lines) - 1,
            ))

        return sections

    @classmethod
    def get_global_config(cls, config: str) -> list[str]:
        """Extract global configuration lines (not in any section)."""
        lines = config.split("\n")
        global_lines = []
        in_section = False

        for line in lines:
            stripped = line.strip()
            if not stripped or stripped.startswith("!"):
                continue

            # Check if entering a section
            if not line.startswith(" ") and not line.startswith("\t"):
                in_section = False
                for pattern, _ in cls.SECTION_PATTERNS.get("cisco_ios", []):
                    if re.match(pattern, stripped, re.IGNORECASE):
                        in_section = True
                        break

                if not in_section:
                    global_lines.append(stripped)
            elif in_section:
                continue  # Skip indented section lines

        return global_lines


# =============================================================================
# Default Templates
# =============================================================================

def get_default_security_template() -> ComplianceTemplate:
    """Get the default security compliance template."""
    return ComplianceTemplate(
        name="security-baseline",
        description="Security baseline for network devices",
        device_roles=["router", "switch"],
        platform="cisco_ios",
        rules=[
            # AAA Rules
            ComplianceRule(
                id="SEC-AAA-001",
                name="AAA New Model",
                description="AAA new-model must be enabled",
                section="global",
                severity=Severity.CRITICAL,
                match_type="present",
                pattern="aaa new-model",
                remediation_template="aaa new-model",
                weight=10,
            ),
            ComplianceRule(
                id="SEC-AAA-002",
                name="AAA Authentication Login",
                description="AAA authentication for login must be configured",
                section="global",
                severity=Severity.CRITICAL,
                match_type="regex",
                pattern=r"aaa authentication login \S+ (local|group)",
                remediation_template="aaa authentication login default local",
                weight=10,
            ),

            # Password Rules
            ComplianceRule(
                id="SEC-PWD-001",
                name="Password Encryption",
                description="Service password-encryption must be enabled",
                section="global",
                severity=Severity.HIGH,
                match_type="present",
                pattern="service password-encryption",
                remediation_template="service password-encryption",
                weight=8,
            ),
            ComplianceRule(
                id="SEC-PWD-002",
                name="Enable Secret",
                description="Enable secret must be configured (not enable password)",
                section="global",
                severity=Severity.CRITICAL,
                match_type="regex",
                pattern=r"enable secret",
                remediation_template="enable secret 0 <PASSWORD>",
                weight=10,
            ),

            # SSH/Telnet Rules
            ComplianceRule(
                id="SEC-SSH-001",
                name="SSH Version 2",
                description="SSH version 1 must NOT be enabled (v2 is default on IOS-XE 17.x)",
                section="global",
                severity=Severity.HIGH,
                match_type="absent",
                pattern="ip ssh version 1",
                remediation_template="ip ssh version 2",
                weight=8,
            ),
            ComplianceRule(
                id="SEC-SSH-002",
                name="No Telnet on VTY",
                description="VTY lines should use SSH only (transport input ssh)",
                section="line",
                severity=Severity.HIGH,
                match_type="present",
                pattern="transport input ssh",
                remediation_template="transport input ssh",
                weight=8,
            ),

            # Logging Rules
            ComplianceRule(
                id="SEC-LOG-001",
                name="Logging Enabled",
                description="Logging must be enabled",
                section="global",
                severity=Severity.MEDIUM,
                match_type="regex",
                pattern=r"logging (host|buffered)",
                remediation_template="logging buffered 16384 informational",
                weight=6,
            ),
            ComplianceRule(
                id="SEC-LOG-002",
                name="Logging Timestamps",
                description="Logging timestamps must be configured",
                section="global",
                severity=Severity.LOW,
                match_type="present",
                pattern="service timestamps log datetime",
                remediation_template="service timestamps log datetime msec localtime show-timezone",
                weight=4,
            ),

            # SNMP Rules
            ComplianceRule(
                id="SEC-SNMP-001",
                name="No SNMP Community Public",
                description="Default 'public' community must not exist",
                section="global",
                severity=Severity.CRITICAL,
                match_type="absent",
                pattern="snmp-server community public",
                remediation_template="no snmp-server community public",
                weight=10,
            ),
            ComplianceRule(
                id="SEC-SNMP-002",
                name="No SNMP Community Private",
                description="Default 'private' community must not exist",
                section="global",
                severity=Severity.CRITICAL,
                match_type="absent",
                pattern="snmp-server community private",
                remediation_template="no snmp-server community private",
                weight=10,
            ),

            # Service Rules
            ComplianceRule(
                id="SEC-SVC-001",
                name="No HTTP Server",
                description="HTTP server should be disabled",
                section="global",
                severity=Severity.MEDIUM,
                match_type="absent",
                pattern="ip http server",
                remediation_template="no ip http server",
                weight=6,
            ),
            ComplianceRule(
                id="SEC-SVC-002",
                name="No IP Source Route",
                description="IP source routing must NOT be enabled (disabled by default on IOS-XE)",
                section="global",
                severity=Severity.HIGH,
                match_type="absent",
                pattern="ip source-route",
                remediation_template="no ip source-route",
                weight=8,
            ),
            ComplianceRule(
                id="SEC-SVC-003",
                name="TCP Keepalives",
                description="TCP keepalives should be enabled",
                section="global",
                severity=Severity.LOW,
                match_type="regex",
                pattern=r"service tcp-keepalives-(in|out)",
                remediation_template="service tcp-keepalives-in\nservice tcp-keepalives-out",
                weight=4,
            ),

            # NTP Rules
            ComplianceRule(
                id="SEC-NTP-001",
                name="NTP Authentication",
                description="NTP authentication should be enabled",
                section="global",
                severity=Severity.MEDIUM,
                match_type="present",
                pattern="ntp authenticate",
                remediation_template="ntp authenticate",
                weight=6,
            ),

            # Banner Rules
            ComplianceRule(
                id="SEC-BAN-001",
                name="Login Banner",
                description="Login banner must be configured",
                section="banner",
                severity=Severity.MEDIUM,
                match_type="regex",
                pattern=r"banner (login|motd)",
                remediation_template="banner login ^C\nUnauthorized access prohibited.\n^C",
                weight=5,
            ),
        ],
    )


def get_default_operational_template() -> ComplianceTemplate:
    """Get the default operational compliance template."""
    return ComplianceTemplate(
        name="operational-baseline",
        description="Operational baseline for network devices",
        device_roles=["router", "switch"],
        platform="cisco_ios",
        rules=[
            # Domain/DNS Rules
            ComplianceRule(
                id="OPS-DNS-001",
                name="Domain Lookup Disabled",
                description="DNS lookup should be disabled on CLI",
                section="global",
                severity=Severity.LOW,
                match_type="present",
                pattern="no ip domain lookup",
                remediation_template="no ip domain lookup",
                weight=3,
            ),

            # Console Rules
            ComplianceRule(
                id="OPS-CON-001",
                name="Console Logging Synchronous",
                description="Console logging should be synchronous",
                section="line",
                severity=Severity.LOW,
                match_type="present",
                pattern="logging synchronous",
                remediation_template="logging synchronous",
                weight=3,
            ),
            ComplianceRule(
                id="OPS-CON-002",
                name="Console Exec Timeout",
                description="Console exec-timeout should be configured",
                section="line",
                severity=Severity.MEDIUM,
                match_type="regex",
                pattern=r"exec-timeout \d+",
                remediation_template="exec-timeout 10 0",
                weight=5,
            ),

            # Archive Rules
            ComplianceRule(
                id="OPS-ARC-001",
                name="Archive Configuration",
                description="Configuration archive should be enabled",
                section="global",
                severity=Severity.MEDIUM,
                match_type="regex",
                pattern=r"archive",
                remediation_template="archive\n path flash:archive\n maximum 14\n write-memory",
                weight=5,
            ),

            # CDP Rules
            ComplianceRule(
                id="OPS-CDP-001",
                name="CDP Enabled",
                description="CDP should be enabled globally",
                section="global",
                severity=Severity.LOW,
                match_type="absent",
                pattern="no cdp run",
                remediation_template="cdp run",
                weight=3,
            ),
        ],
    )


# =============================================================================
# Compliance Engine
# =============================================================================

class ComplianceEngine:
    """
    Configuration compliance engine with section-based comparison.
    """

    def __init__(self, templates_dir: Path = None, db_path: Path = None, db: UnifiedDB = None):
        self.templates_dir = templates_dir or TEMPLATES_DIR
        self.db = db or UnifiedDB.get_instance()
        self.db_path = db_path or self.db.db_path
        self.templates: dict[str, ComplianceTemplate] = {}

        # Ensure directories exist
        self.templates_dir.mkdir(parents=True, exist_ok=True)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

        # Initialize database (standalone mode only)
        if db_path and not db:
            self._init_db()

        # Load templates
        self._load_templates()

    def _connect(self) -> sqlite3.Connection:
        """Get a database connection (unified or standalone)."""
        if self.db:
            return self.db.connect()
        return sqlite3.connect(self.db_path)

    def _init_db(self):
        """Initialize SQLite database for compliance history (standalone mode)."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS compliance_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    device TEXT NOT NULL,
                    template TEXT NOT NULL,
                    status TEXT NOT NULL,
                    score REAL NOT NULL,
                    total_rules INTEGER NOT NULL,
                    passed_rules INTEGER NOT NULL,
                    failed_rules INTEGER NOT NULL,
                    violations_json TEXT,
                    checked_at TEXT NOT NULL,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_compliance_device
                ON compliance_history(device, checked_at)
            """)
            conn.commit()

    def _load_templates(self):
        """Load compliance templates from files and defaults."""
        # Load default templates
        self.templates["security-baseline"] = get_default_security_template()
        self.templates["operational-baseline"] = get_default_operational_template()

        # Load custom templates from files
        if self.templates_dir.exists():
            for template_file in self.templates_dir.glob("*.json"):
                try:
                    with open(template_file) as f:
                        data = json.load(f)

                    rules = [
                        ComplianceRule(
                            id=r["id"],
                            name=r["name"],
                            description=r.get("description", ""),
                            section=r["section"],
                            severity=Severity(r.get("severity", "medium")),
                            match_type=r["match_type"],
                            pattern=r["pattern"],
                            remediation_template=r.get("remediation_template", ""),
                            weight=r.get("weight", 1),
                            enabled=r.get("enabled", True),
                        )
                        for r in data.get("rules", [])
                    ]

                    template = ComplianceTemplate(
                        name=data["name"],
                        description=data.get("description", ""),
                        device_roles=data.get("device_roles", []),
                        platform=data.get("platform", "cisco_ios"),
                        rules=rules,
                        version=data.get("version", "1.0"),
                    )

                    self.templates[template.name] = template
                    logger.info(f"Loaded compliance template: {template.name}")

                except Exception as e:
                    logger.error(f"Failed to load template {template_file}: {e}")

    def list_templates(self) -> list[dict]:
        """List available compliance templates."""
        return [
            {
                "name": t.name,
                "description": t.description,
                "device_roles": t.device_roles,
                "platform": t.platform,
                "rule_count": len(t.rules),
                "version": t.version,
            }
            for t in self.templates.values()
        ]

    def get_template(self, name: str) -> Optional[ComplianceTemplate]:
        """Get a specific template by name."""
        return self.templates.get(name)

    async def check_compliance(
        self,
        device_name: str,
        template_name: str = "security-baseline",
        config: str = None,
    ) -> ComplianceResult:
        """
        Check device compliance against a template.

        Args:
            device_name: Device name from inventory
            template_name: Template to check against
            config: Optional config string (fetched if not provided)

        Returns:
            ComplianceResult with violations and score
        """
        template = self.templates.get(template_name)
        if not template:
            return ComplianceResult(
                device=device_name,
                template=template_name,
                status=ComplianceStatus.ERROR,
                score=0,
                checked_at=isonow(),
                total_rules=0,
                passed_rules=0,
                failed_rules=0,
                error=f"Template '{template_name}' not found",
            )

        # Fetch config if not provided
        if not config:
            config = await self._fetch_config(device_name)
            if not config:
                return ComplianceResult(
                    device=device_name,
                    template=template_name,
                    status=ComplianceStatus.ERROR,
                    score=0,
                    checked_at=isonow(),
                    total_rules=0,
                    passed_rules=0,
                    failed_rules=0,
                    error=f"Failed to fetch config from {device_name}",
                )

        # Determine platform for parsing
        parse_platform = template.platform
        try:
            from config.devices import DEVICES
            device_type = DEVICES.get(device_name, {}).get("device_type", "")
            mapped = ConfigParser.PLATFORM_MAP.get(device_type)
            if mapped:
                parse_platform = mapped
        except ImportError:
            pass

        # Parse config into sections
        sections = ConfigParser.parse(config, parse_platform)
        global_config = ConfigParser.get_global_config(config)

        # Check each rule
        violations = []
        passed = 0
        total_weight = 0
        passed_weight = 0
        sections_checked = set()

        for rule in template.rules:
            if not rule.enabled:
                continue

            total_weight += rule.weight
            sections_checked.add(rule.section)

            # Determine which config lines to check
            if rule.section == "global":
                lines_to_check = global_config
            else:
                # Find matching sections
                matching_sections = [s for s in sections if s.name == rule.section]
                lines_to_check = []
                for s in matching_sections:
                    lines_to_check.extend(s.lines)

            # Check the rule
            is_compliant = self._check_rule(rule, lines_to_check, config)

            if is_compliant:
                passed += 1
                passed_weight += rule.weight
            else:
                violation = ComplianceViolation(
                    section=rule.section,
                    rule_id=rule.id,
                    rule_name=rule.name,
                    severity=rule.severity,
                    expected=f"{rule.match_type}: {rule.pattern}",
                    actual="Not found" if rule.match_type in ("present", "regex") else "Found",
                    remediation=rule.remediation_template,
                    weight=rule.weight,
                )
                violations.append(violation)

        # Calculate score
        score = (passed_weight / total_weight * 100) if total_weight > 0 else 100

        # Determine status
        if not violations:
            status = ComplianceStatus.COMPLIANT
        elif score >= 80:
            status = ComplianceStatus.PARTIAL
        else:
            status = ComplianceStatus.NON_COMPLIANT

        # Generate remediation commands
        remediation_commands = []
        for v in violations:
            if v.remediation:
                for line in v.remediation.split("\n"):
                    if line.strip():
                        remediation_commands.append(line.strip())

        result = ComplianceResult(
            device=device_name,
            template=template_name,
            status=status,
            score=score,
            checked_at=isonow(),
            total_rules=len([r for r in template.rules if r.enabled]),
            passed_rules=passed,
            failed_rules=len(violations),
            violations=violations,
            remediation_commands=remediation_commands,
            sections_checked=list(sections_checked),
        )

        # Save to history
        self._save_result(result)

        return result

    def _check_rule(self, rule: ComplianceRule, lines: list[str], full_config: str) -> bool:
        """Check if a rule is satisfied."""
        config_text = "\n".join(lines)

        if rule.match_type == "present":
            # Line must be present
            return rule.pattern.lower() in full_config.lower()

        elif rule.match_type == "absent":
            # Line must NOT be present (as a complete command, not as substring)
            # Use regex with line start anchor to avoid matching "no <pattern>" as "<pattern>"
            pattern = r"^\s*" + re.escape(rule.pattern) + r"\s*$"
            return not bool(re.search(pattern, full_config, re.IGNORECASE | re.MULTILINE))

        elif rule.match_type == "regex":
            # Pattern must match somewhere
            return bool(re.search(rule.pattern, full_config, re.IGNORECASE | re.MULTILINE))

        elif rule.match_type == "exact":
            # Exact line match
            return any(line.strip() == rule.pattern for line in lines)

        return False

    async def _fetch_config(self, device_name: str) -> Optional[str]:
        """Fetch running config from device. Supports Cisco IOS-XE, FRR, and SR Linux."""
        try:
            from config.devices import DEVICES

            if device_name not in DEVICES:
                return None

            device = DEVICES[device_name]
            device_type = device.get("device_type", "")

            if device_type in ("cisco_xe", "cisco_ios"):
                from core.scrapli_manager import get_ios_xe_connection
                async with get_ios_xe_connection(device_name) as conn:
                    response = await conn.send_command("show running-config")
                    return response.result

            elif device_type == "containerlab_frr":
                from core.containerlab import get_containerlab_command_output
                return await get_containerlab_command_output(
                    device_name, "show running-config"
                )

            elif device_type == "containerlab_srlinux":
                from core.containerlab import get_containerlab_command_output
                return await get_containerlab_command_output(
                    device_name, "info flat"
                )

            else:
                logger.warning(f"Unsupported device type for compliance: {device_type}")
                return None

        except Exception as e:
            logger.error(f"Failed to fetch config from {device_name}: {e}")
            return None

    def _save_result(self, result: ComplianceResult):
        """Save compliance result to history."""
        try:
            with self._connect() as conn:
                conn.execute("""
                    INSERT INTO compliance_history
                    (device, template, status, score, total_rules, passed_rules,
                     failed_rules, violations_json, checked_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    result.device,
                    result.template,
                    result.status.value,
                    result.score,
                    result.total_rules,
                    result.passed_rules,
                    result.failed_rules,
                    json.dumps([v.to_dict() for v in result.violations]),
                    result.checked_at,
                ))
                conn.commit()
        except Exception as e:
            logger.error(f"Failed to save compliance result: {e}")

    async def check_all_devices(
        self,
        template_name: str = "security-baseline",
        device_names: list[str] = None,
        max_concurrent: int = 5,
    ) -> list[ComplianceResult]:
        """
        Check compliance for multiple devices in parallel.

        Args:
            template_name: Template to check against
            device_names: List of devices (all if None)
            max_concurrent: Max concurrent checks

        Returns:
            List of ComplianceResult
        """
        from config.devices import DEVICES

        if device_names is None:
            supported_types = {"cisco_xe", "cisco_ios", "containerlab_frr", "containerlab_srlinux"}
            device_names = [
                name for name, cfg in DEVICES.items()
                if cfg.get("device_type") in supported_types
            ]

        semaphore = asyncio.Semaphore(max_concurrent)

        async def check_with_semaphore(device: str) -> ComplianceResult:
            async with semaphore:
                return await self.check_compliance(device, template_name)

        results = await asyncio.gather(
            *[check_with_semaphore(d) for d in device_names],
            return_exceptions=True,
        )

        # Convert exceptions to error results
        final_results = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                final_results.append(ComplianceResult(
                    device=device_names[i],
                    template=template_name,
                    status=ComplianceStatus.ERROR,
                    score=0,
                    checked_at=isonow(),
                    total_rules=0,
                    passed_rules=0,
                    failed_rules=0,
                    error=str(result),
                ))
            else:
                final_results.append(result)

        return final_results

    def get_compliance_history(
        self,
        device_name: str = None,
        days: int = 30,
        template_name: str = None,
    ) -> list[dict]:
        """
        Get compliance history.

        Args:
            device_name: Filter by device (all if None)
            days: Number of days to look back
            template_name: Filter by template (all if None)

        Returns:
            List of historical compliance records
        """
        cutoff = (now() - timedelta(days=days)).isoformat()

        query = """
            SELECT device, template, status, score, total_rules,
                   passed_rules, failed_rules, checked_at
            FROM compliance_history
            WHERE checked_at >= ?
        """
        params = [cutoff]

        if device_name:
            query += " AND device = ?"
            params.append(device_name)

        if template_name:
            query += " AND template = ?"
            params.append(template_name)

        query += " ORDER BY checked_at DESC"

        with self._connect() as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute(query, params)
            return [dict(row) for row in cursor.fetchall()]

    def get_compliance_trend(
        self,
        device_name: str,
        days: int = 30,
        template_name: str = "security-baseline",
    ) -> dict:
        """
        Get compliance score trend for a device.

        Returns:
            Dict with trend data points
        """
        history = self.get_compliance_history(device_name, days, template_name)

        if not history:
            return {"device": device_name, "data_points": []}

        return {
            "device": device_name,
            "template": template_name,
            "data_points": [
                {
                    "checked_at": h["checked_at"],
                    "score": h["score"],
                    "status": h["status"],
                }
                for h in history
            ],
            "current_score": history[0]["score"] if history else None,
            "trend": self._calculate_trend([h["score"] for h in history]),
        }

    def _calculate_trend(self, scores: list[float]) -> str:
        """Calculate trend direction from scores."""
        if len(scores) < 2:
            return "stable"

        recent = scores[:min(5, len(scores))]
        older = scores[min(5, len(scores)):min(10, len(scores))]

        if not older:
            return "stable"

        recent_avg = sum(recent) / len(recent)
        older_avg = sum(older) / len(older)

        diff = recent_avg - older_avg

        if diff > 5:
            return "improving"
        elif diff < -5:
            return "declining"
        else:
            return "stable"


# =============================================================================
# Global Instance
# =============================================================================

_engine: Optional[ComplianceEngine] = None


def get_compliance_engine() -> ComplianceEngine:
    """Get the global compliance engine instance."""
    global _engine
    if _engine is None:
        _engine = ComplianceEngine()
    return _engine
