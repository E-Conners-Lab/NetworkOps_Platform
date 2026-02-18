"""
pyATS Integration Tools for Network MCP Server

Provides structured parsing, state comparison, and compliance checking
using Cisco pyATS/Genie framework.
"""

import sys
import json
import yaml
from datetime import datetime
from pathlib import Path

# Add project root to path for shared config imports
sys.path.insert(0, str(Path(__file__).parent.parent))

# pyATS/Genie imports
from genie.testbed import load as load_testbed
from genie.utils.diff import Diff
from genie.libs.parser.utils import get_parser

# Shared device configuration (single source of truth)
from config.devices import DEVICES as SHARED_DEVICES, USERNAME, PASSWORD

# Build pyATS-compatible device dict from shared config
# pyATS needs 'os' and 'type' fields instead of 'device_type'
DEVICES = {}
for name, device in SHARED_DEVICES.items():
    device_type = device.get("device_type", "")
    if device_type == "cisco_xe":
        # Determine if router or switch based on name
        dev_type = "switch" if "Switch" in name else "router"
        DEVICES[name] = {
            "host": device["host"],
            "os": "iosxe",
            "type": dev_type,
        }

# Baselines directory (in data/ folder)
BASELINES_DIR = Path(__file__).parent.parent / "data" / "baselines"
GOLDEN_CONFIGS_DIR = Path(__file__).parent.parent / "data" / "golden_configs"

# Supported features for learning
SUPPORTED_FEATURES = ["ospf", "eigrp", "interface", "routing", "bgp", "vrf", "arp", "platform"]


def create_testbed_dict() -> dict:
    """
    Convert DEVICES inventory to pyATS testbed dictionary format.

    Returns:
        dict: pyATS testbed structure
    """
    testbed = {
        "testbed": {
            "name": "network_lab",
            "credentials": {
                "default": {
                    "username": USERNAME,
                    "password": PASSWORD,
                }
            }
        },
        "devices": {}
    }

    for device_name, device_info in DEVICES.items():
        testbed["devices"][device_name] = {
            "os": device_info["os"],
            "type": device_info["type"],
            "connections": {
                "cli": {
                    "protocol": "ssh",
                    "ip": device_info["host"],
                    "port": 22,
                }
            },
            "credentials": {
                "default": {
                    "username": USERNAME,
                    "password": PASSWORD,
                }
            }
        }

    return testbed


def get_testbed():
    """
    Create and return a pyATS testbed object.

    Returns:
        Testbed: pyATS testbed object
    """
    testbed_dict = create_testbed_dict()
    return load_testbed(testbed_dict)


def generate_testbed() -> str:
    """
    Generate pyATS testbed YAML from device inventory.

    Returns the testbed configuration that can be used with pyATS
    for automated testing and validation.

    Returns:
        str: JSON with testbed YAML and device count
    """
    try:
        testbed_dict = create_testbed_dict()
        testbed_yaml = yaml.dump(testbed_dict, default_flow_style=False, sort_keys=False)

        return json.dumps({
            "status": "success",
            "device_count": len(DEVICES),
            "devices": list(DEVICES.keys()),
            "testbed_yaml": testbed_yaml
        }, indent=2)

    except Exception as e:
        return json.dumps({
            "status": "error",
            "error": str(e)
        }, indent=2)


def learn_feature(device_name: str, feature: str) -> str:
    """
    Learn device feature state using Genie parsers.

    Supported features: ospf, eigrp, interface, routing, bgp, vrf, arp, platform

    Args:
        device_name: Name of device (R1, R2, etc.)
        feature: Feature to learn (ospf, eigrp, interface, routing, bgp)

    Returns:
        str: JSON with structured feature state
    """
    if device_name not in DEVICES:
        return json.dumps({
            "status": "error",
            "error": f"Device '{device_name}' not found. Available: {list(DEVICES.keys())}"
        }, indent=2)

    feature = feature.lower()
    if feature not in SUPPORTED_FEATURES:
        return json.dumps({
            "status": "error",
            "error": f"Feature '{feature}' not supported. Available: {SUPPORTED_FEATURES}"
        }, indent=2)

    try:
        testbed = get_testbed()
        device = testbed.devices[device_name]
        device.connect(log_stdout=False)

        # Learn the feature
        learned = device.learn(feature)

        device.disconnect()

        # Convert to dict for JSON serialization
        if hasattr(learned, 'info'):
            feature_data = learned.info
        else:
            feature_data = learned.__dict__ if hasattr(learned, '__dict__') else str(learned)

        return json.dumps({
            "status": "success",
            "device": device_name,
            "feature": feature,
            "timestamp": datetime.now().isoformat(),
            "data": feature_data
        }, indent=2)

    except Exception as e:
        return json.dumps({
            "status": "error",
            "device": device_name,
            "feature": feature,
            "error": str(e)
        }, indent=2)


def snapshot_state(device_name: str, label: str = "baseline") -> str:
    """
    Capture device state to baseline file.

    Captures key features (interface, ospf, eigrp, routing) and saves
    to baselines/{device}_{label}.json for later comparison.

    Args:
        device_name: Name of device (R1, R2, etc.)
        label: Label for baseline file (default: "baseline")

    Returns:
        str: JSON with snapshot status and file path
    """
    if device_name not in DEVICES:
        return json.dumps({
            "status": "error",
            "error": f"Device '{device_name}' not found. Available: {list(DEVICES.keys())}"
        }, indent=2)

    # Ensure baselines directory exists
    BASELINES_DIR.mkdir(parents=True, exist_ok=True)

    try:
        testbed = get_testbed()
        device = testbed.devices[device_name]
        device.connect(log_stdout=False)

        snapshot = {
            "device": device_name,
            "label": label,
            "timestamp": datetime.now().isoformat(),
            "features": {}
        }

        # Learn key features
        features_to_capture = ["interface", "routing"]

        # Add protocol features based on device type
        if DEVICES[device_name]["type"] == "router":
            features_to_capture.extend(["ospf", "eigrp"])
        else:
            features_to_capture.append("eigrp")

        for feature in features_to_capture:
            try:
                learned = device.learn(feature)
                if hasattr(learned, 'info'):
                    snapshot["features"][feature] = learned.info
                else:
                    snapshot["features"][feature] = {"raw": str(learned)}
            except Exception as e:
                snapshot["features"][feature] = {"error": str(e)}

        device.disconnect()

        # Save to file
        filename = f"{device_name}_{label}.json"
        filepath = BASELINES_DIR / filename

        with open(filepath, 'w') as f:
            json.dump(snapshot, f, indent=2, default=str)

        return json.dumps({
            "status": "success",
            "device": device_name,
            "label": label,
            "filepath": str(filepath),
            "features_captured": list(snapshot["features"].keys()),
            "timestamp": snapshot["timestamp"]
        }, indent=2)

    except Exception as e:
        return json.dumps({
            "status": "error",
            "device": device_name,
            "error": str(e)
        }, indent=2)


def _to_dict(obj):
    """
    Recursively convert Genie objects to plain dicts for comparison.

    Handles CmdDict, AttrDict, and other Genie container types.
    """
    if isinstance(obj, dict):
        return {k: _to_dict(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [_to_dict(item) for item in obj]
    else:
        return obj


def diff_state(device_name: str, label: str = "baseline") -> str:
    """
    Compare current device state against saved baseline.

    Reads baseline from baselines/{device}_{label}.json and compares
    with current device state.

    Args:
        device_name: Name of device (R1, R2, etc.)
        label: Label of baseline to compare against (default: "baseline")

    Returns:
        str: JSON with differences found
    """
    if device_name not in DEVICES:
        return json.dumps({
            "status": "error",
            "error": f"Device '{device_name}' not found. Available: {list(DEVICES.keys())}"
        }, indent=2)

    # Load baseline
    filename = f"{device_name}_{label}.json"
    filepath = BASELINES_DIR / filename

    if not filepath.exists():
        return json.dumps({
            "status": "error",
            "error": f"Baseline not found: {filepath}. Run snapshot_state first."
        }, indent=2)

    with open(filepath, 'r') as f:
        baseline = json.load(f)

    try:
        testbed = get_testbed()
        device = testbed.devices[device_name]
        device.connect(log_stdout=False)

        result = {
            "device": device_name,
            "baseline_label": label,
            "baseline_timestamp": baseline.get("timestamp"),
            "current_timestamp": datetime.now().isoformat(),
            "changes": {},
            "summary": {"total_changes": 0, "features_changed": []}
        }

        # Compare each feature in baseline
        for feature, baseline_data in baseline.get("features", {}).items():
            if "error" in baseline_data:
                continue

            try:
                learned = device.learn(feature)
                if hasattr(learned, 'info'):
                    current_data = _to_dict(learned.info)
                else:
                    current_data = {"raw": str(learned)}

                # Use Genie Diff (both sides now plain dicts)
                diff = Diff(baseline_data, current_data)
                diff.findDiff()

                if diff.diffs:
                    result["changes"][feature] = {
                        "diff": str(diff),
                        "has_changes": True
                    }
                    result["summary"]["features_changed"].append(feature)
                    result["summary"]["total_changes"] += 1
                else:
                    result["changes"][feature] = {
                        "diff": None,
                        "has_changes": False
                    }

            except Exception as e:
                result["changes"][feature] = {
                    "error": str(e),
                    "has_changes": "unknown"
                }

        device.disconnect()

        result["status"] = "success"
        return json.dumps(result, indent=2, default=str)

    except Exception as e:
        return json.dumps({
            "status": "error",
            "device": device_name,
            "error": str(e)
        }, indent=2)


def check_compliance(device_name: str, template: str = "default") -> str:
    """
    Check running config against golden template.

    Validates that required configuration lines are present in
    the device's running config.

    Args:
        device_name: Name of device (R1, R2, etc.)
        template: Template name in data/golden_configs/ (default: "default")

    Returns:
        str: JSON with compliance status and violations
    """
    if device_name not in DEVICES:
        return json.dumps({
            "status": "error",
            "error": f"Device '{device_name}' not found. Available: {list(DEVICES.keys())}"
        }, indent=2)

    # Determine template file based on device type
    device_type = DEVICES[device_name]["type"]
    template_file = GOLDEN_CONFIGS_DIR / f"{template}_{device_type}.txt"

    # Fall back to default template
    if not template_file.exists():
        template_file = GOLDEN_CONFIGS_DIR / f"{template}.txt"

    if not template_file.exists():
        return json.dumps({
            "status": "error",
            "error": f"Template not found: {template_file}. Create golden config first."
        }, indent=2)

    # Load template (list of required config lines)
    with open(template_file, 'r') as f:
        required_lines = [line.strip() for line in f.readlines()
                        if line.strip() and not line.startswith('#')]

    try:
        testbed = get_testbed()
        device = testbed.devices[device_name]
        device.connect(log_stdout=False)

        # Get running config
        running_config = device.execute("show running-config")

        device.disconnect()

        # Check each required line
        violations = []
        compliant_lines = []

        for required in required_lines:
            # Support for regex patterns (lines starting with '^')
            if required.startswith('^'):
                import re
                pattern = required[1:]
                if not re.search(pattern, running_config, re.MULTILINE):
                    violations.append({
                        "line": required,
                        "type": "regex_missing",
                        "expected": True,
                        "found": False
                    })
                else:
                    compliant_lines.append(required)
            # Support for negative checks (lines starting with '!')
            elif required.startswith('!'):
                check_line = required[1:]
                if check_line in running_config:
                    violations.append({
                        "line": check_line,
                        "type": "should_not_exist",
                        "expected": False,
                        "found": True
                    })
                else:
                    compliant_lines.append(required)
            # Standard line check
            else:
                if required not in running_config:
                    violations.append({
                        "line": required,
                        "type": "missing",
                        "expected": True,
                        "found": False
                    })
                else:
                    compliant_lines.append(required)

        total_checks = len(required_lines)
        passed_checks = len(compliant_lines)

        return json.dumps({
            "status": "success",
            "device": device_name,
            "template": template,
            "compliant": len(violations) == 0,
            "score": f"{passed_checks}/{total_checks}",
            "percentage": round(passed_checks / total_checks * 100, 1) if total_checks > 0 else 100,
            "violations": violations,
            "summary": f"{len(violations)} violation(s) found"
        }, indent=2)

    except Exception as e:
        return json.dumps({
            "status": "error",
            "device": device_name,
            "error": str(e)
        }, indent=2)


def list_baselines() -> str:
    """
    List all saved baseline snapshots.

    Returns:
        str: JSON with list of available baselines
    """
    if not BASELINES_DIR.exists():
        return json.dumps({
            "status": "success",
            "baselines": [],
            "message": "No baselines directory found"
        }, indent=2)

    baselines = []
    for filepath in BASELINES_DIR.glob("*.json"):
        try:
            with open(filepath, 'r') as f:
                data = json.load(f)
            baselines.append({
                "filename": filepath.name,
                "device": data.get("device"),
                "label": data.get("label"),
                "timestamp": data.get("timestamp"),
                "features": list(data.get("features", {}).keys())
            })
        except Exception:
            baselines.append({
                "filename": filepath.name,
                "error": "Could not parse"
            })

    return json.dumps({
        "status": "success",
        "baselines_dir": str(BASELINES_DIR),
        "count": len(baselines),
        "baselines": baselines
    }, indent=2)


def list_templates() -> str:
    """
    List available golden config templates.

    Returns:
        str: JSON with list of available templates
    """
    if not GOLDEN_CONFIGS_DIR.exists():
        return json.dumps({
            "status": "success",
            "templates": [],
            "message": "No golden_configs directory found"
        }, indent=2)

    templates = []
    for filepath in GOLDEN_CONFIGS_DIR.glob("*.txt"):
        with open(filepath, 'r') as f:
            lines = [l.strip() for l in f.readlines()
                    if l.strip() and not l.startswith('#')]
        templates.append({
            "filename": filepath.name,
            "template_name": filepath.stem,
            "check_count": len(lines)
        })

    return json.dumps({
        "status": "success",
        "templates_dir": str(GOLDEN_CONFIGS_DIR),
        "count": len(templates),
        "templates": templates
    }, indent=2)


# =============================================================================
# Security Audit Rules
# =============================================================================

SECURITY_RULES = {
    "telnet_enabled": {
        "check": lambda cfg: "transport input telnet" in cfg or "transport input all" in cfg,
        "severity": "critical",
        "description": "Telnet enabled on VTY lines (unencrypted)",
        "remediation": "transport input ssh"
    },
    "no_service_password_encryption": {
        "check": lambda cfg: "no service password-encryption" in cfg,
        "severity": "high",
        "description": "Password encryption disabled",
        "remediation": "service password-encryption"
    },
    "http_server_enabled": {
        "check": lambda cfg: "ip http server" in cfg and "no ip http server" not in cfg,
        "severity": "medium",
        "description": "HTTP server enabled (use HTTPS instead)",
        "remediation": "no ip http server"
    },
    "weak_enable_password": {
        "check": lambda cfg: "enable password " in cfg and "enable secret" not in cfg,
        "severity": "high",
        "description": "Using weak 'enable password' instead of 'enable secret'",
        "remediation": "enable secret <password>"
    },
    "no_logging_buffered": {
        "check": lambda cfg: "logging buffered" not in cfg,
        "severity": "medium",
        "description": "Local logging not configured",
        "remediation": "logging buffered 16384 informational"
    },
    "no_ntp_configured": {
        "check": lambda cfg: "ntp server" not in cfg and "ntp peer" not in cfg,
        "severity": "medium",
        "description": "No NTP server configured",
        "remediation": "ntp server <ip-address>"
    },
    "snmp_v1_v2_community": {
        "check": lambda cfg: "snmp-server community" in cfg and "snmp-server group" not in cfg,
        "severity": "medium",
        "description": "Using SNMPv1/v2c community strings instead of SNMPv3",
        "remediation": "Configure SNMPv3 with authentication and encryption"
    },
    "no_exec_timeout": {
        "check": lambda cfg: "exec-timeout 0 0" in cfg,
        "severity": "medium",
        "description": "Exec timeout disabled on console/VTY",
        "remediation": "exec-timeout 10 0"
    },
    "ip_source_route": {
        "check": lambda cfg: "ip source-route" in cfg and "no ip source-route" not in cfg,
        "severity": "low",
        "description": "IP source routing enabled",
        "remediation": "no ip source-route"
    },
    "no_login_banner": {
        "check": lambda cfg: "banner login" not in cfg and "banner motd" not in cfg,
        "severity": "low",
        "description": "No login banner configured",
        "remediation": "banner login ^Authorized access only^"
    },
    "weak_ssh_version": {
        "check": lambda cfg: "ip ssh version 1" in cfg,
        "severity": "critical",
        "description": "SSH version 1 enabled (vulnerable)",
        "remediation": "ip ssh version 2"
    },
    "no_aaa": {
        "check": lambda cfg: "aaa new-model" not in cfg,
        "severity": "high",
        "description": "AAA not configured",
        "remediation": "aaa new-model"
    },
    "cdp_enabled_globally": {
        "check": lambda cfg: "no cdp run" not in cfg,
        "severity": "low",
        "description": "CDP enabled globally (information disclosure)",
        "remediation": "no cdp run (or disable per-interface on untrusted ports)"
    },
    "aux_port_enabled": {
        "check": lambda cfg: "line aux 0" in cfg and "no exec" not in cfg.split("line aux 0")[1].split("line")[0] if "line aux 0" in cfg else False,
        "severity": "medium",
        "description": "AUX port may allow exec sessions",
        "remediation": "line aux 0 -> no exec"
    },
    "no_tcp_keepalives": {
        "check": lambda cfg: "service tcp-keepalives-in" not in cfg,
        "severity": "low",
        "description": "TCP keepalives not configured",
        "remediation": "service tcp-keepalives-in / service tcp-keepalives-out"
    }
}


def security_audit(device_name: str = None) -> str:
    """
    Check device(s) for common security misconfigurations.

    Checks 15+ security rules including:
    - Telnet/SSH settings
    - Password encryption
    - Logging configuration
    - SNMP security
    - AAA configuration
    - Service hardening

    Args:
        device_name: Specific device to audit, or None for all devices

    Returns:
        str: JSON with security findings and remediation advice
    """
    import re

    devices_to_check = [device_name] if device_name else list(DEVICES.keys())

    # Validate device exists
    for dev in devices_to_check:
        if dev not in DEVICES:
            return json.dumps({
                "status": "error",
                "error": f"Device '{dev}' not found. Available: {list(DEVICES.keys())}"
            }, indent=2)

    try:
        testbed = get_testbed()
        results = {
            "status": "success",
            "timestamp": datetime.now().isoformat(),
            "devices_audited": len(devices_to_check),
            "results": {},
            "summary": {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "total_findings": 0
            }
        }

        for dev_name in devices_to_check:
            device = testbed.devices[dev_name]
            device.connect(log_stdout=False)

            # Get running config
            config = device.execute("show running-config")

            device.disconnect()

            findings = []
            device_summary = {"critical": 0, "high": 0, "medium": 0, "low": 0}

            for rule_name, rule in SECURITY_RULES.items():
                try:
                    if rule["check"](config):
                        findings.append({
                            "rule": rule_name,
                            "severity": rule["severity"],
                            "description": rule["description"],
                            "remediation": rule["remediation"]
                        })
                        device_summary[rule["severity"]] += 1
                        results["summary"][rule["severity"]] += 1
                        results["summary"]["total_findings"] += 1
                except Exception:
                    pass  # Skip rules that error

            # Calculate security score (100 - penalties)
            penalty = (device_summary["critical"] * 25 +
                      device_summary["high"] * 15 +
                      device_summary["medium"] * 5 +
                      device_summary["low"] * 2)
            score = max(0, 100 - penalty)

            results["results"][dev_name] = {
                "findings_count": len(findings),
                "security_score": score,
                "grade": "A" if score >= 90 else "B" if score >= 75 else "C" if score >= 60 else "D" if score >= 40 else "F",
                "summary": device_summary,
                "findings": findings
            }

        # Overall grade
        if results["devices_audited"] > 0:
            avg_score = sum(r["security_score"] for r in results["results"].values()) / results["devices_audited"]
            results["overall_score"] = round(avg_score, 1)
            results["overall_grade"] = "A" if avg_score >= 90 else "B" if avg_score >= 75 else "C" if avg_score >= 60 else "D" if avg_score >= 40 else "F"

        return json.dumps(results, indent=2)

    except Exception as e:
        return json.dumps({
            "status": "error",
            "error": str(e)
        }, indent=2)


# =============================================================================
# CVE Check (Version-based vulnerability assessment)
# =============================================================================

# Known CVEs for IOS-XE versions (expanded Dec 2025)
# In production, consider using NIST NVD API or Cisco PSIRT OpenVuln API
KNOWN_CVES = {
    "17.3": [
        {"id": "CVE-2021-1385", "severity": "high", "description": "Web UI RCE vulnerability"},
        {"id": "CVE-2021-34770", "severity": "critical", "description": "Arbitrary code execution in WLAN"},
        {"id": "CVE-2021-1619", "severity": "critical", "description": "AAA bypass via crafted NETCONF/RESTCONF"},
    ],
    "17.6": [
        {"id": "CVE-2022-20695", "severity": "critical", "description": "Wireless LAN Controller auth bypass"},
        {"id": "CVE-2022-20692", "severity": "high", "description": "IKEv2 DoS vulnerability"},
        {"id": "CVE-2022-20830", "severity": "high", "description": "SSH denial of service"},
    ],
    "17.9": [
        {"id": "CVE-2023-20198", "severity": "critical", "description": "Web UI privilege escalation (actively exploited)"},
        {"id": "CVE-2023-20273", "severity": "high", "description": "Web UI command injection"},
        {"id": "CVE-2023-20109", "severity": "medium", "description": "Group Encrypted Transport VPN out-of-bounds write"},
        {"id": "CVE-2023-20231", "severity": "high", "description": "Web UI command injection (another vector)"},
    ],
    "17.10": [
        {"id": "CVE-2023-20198", "severity": "critical", "description": "Web UI privilege escalation"},
        {"id": "CVE-2024-20295", "severity": "high", "description": "IMC CLI command injection"},
        {"id": "CVE-2024-20259", "severity": "high", "description": "DHCP snooping DoS"},
    ],
    "17.11": [
        {"id": "CVE-2024-20311", "severity": "high", "description": "Locator/ID Separation Protocol DoS"},
        {"id": "CVE-2024-20314", "severity": "medium", "description": "IPv4 Software-Defined Access DoS"},
        {"id": "CVE-2024-20278", "severity": "medium", "description": "Privilege escalation via IOx"},
    ],
    "17.12": [
        {"id": "CVE-2024-20303", "severity": "high", "description": "DHCP snooping DoS"},
        {"id": "CVE-2024-20324", "severity": "medium", "description": "Privilege escalation via CLI"},
        {"id": "CVE-2024-20316", "severity": "medium", "description": "HTTP Server path traversal"},
    ],
    "17.13": [
        # 17.13.1a is current - no critical CVEs as of Dec 2025
        # Check Cisco Security Advisories: https://sec.cloudapps.cisco.com/security/center/publicationListing.x
    ],
}


def cve_check(device_name: str = None) -> str:
    """
    Check device software versions against known CVE database.

    Cross-references IOS-XE version with known vulnerabilities.

    Args:
        device_name: Specific device to check, or None for all devices

    Returns:
        str: JSON with CVE exposure report
    """
    import re

    devices_to_check = [device_name] if device_name else list(DEVICES.keys())

    for dev in devices_to_check:
        if dev not in DEVICES:
            return json.dumps({
                "status": "error",
                "error": f"Device '{dev}' not found. Available: {list(DEVICES.keys())}"
            }, indent=2)

    try:
        testbed = get_testbed()
        results = {
            "status": "success",
            "timestamp": datetime.now().isoformat(),
            "devices_checked": len(devices_to_check),
            "results": {},
            "summary": {
                "devices_at_risk": 0,
                "total_cves": 0,
                "critical_cves": 0,
                "high_cves": 0
            }
        }

        for dev_name in devices_to_check:
            device = testbed.devices[dev_name]
            device.connect(log_stdout=False)

            # Get version info
            version_output = device.execute("show version")

            device.disconnect()

            # Parse version
            version_match = re.search(r'Version\s+(\d+\.\d+)', version_output)
            version = version_match.group(1) if version_match else "unknown"

            # Check for CVEs
            device_cves = []
            for ver_prefix, cves in KNOWN_CVES.items():
                if version.startswith(ver_prefix):
                    device_cves.extend(cves)

            # Count severities
            critical = sum(1 for c in device_cves if c["severity"] == "critical")
            high = sum(1 for c in device_cves if c["severity"] == "high")

            results["results"][dev_name] = {
                "version": version,
                "cves_found": len(device_cves),
                "risk_level": "critical" if critical > 0 else "high" if high > 0 else "low" if device_cves else "none",
                "cves": device_cves,
                "recommendation": "Upgrade to latest stable version" if device_cves else "Version appears current"
            }

            if device_cves:
                results["summary"]["devices_at_risk"] += 1
                results["summary"]["total_cves"] += len(device_cves)
                results["summary"]["critical_cves"] += critical
                results["summary"]["high_cves"] += high

        return json.dumps(results, indent=2)

    except Exception as e:
        return json.dumps({
            "status": "error",
            "error": str(e)
        }, indent=2)


# =============================================================================
# Interface Report (Utilization, errors, top talkers)
# =============================================================================

def interface_report(device_name: str = None, top_n: int = 10) -> str:
    """
    Generate interface utilization and error report.

    Uses pyATS to learn interface state and calculate:
    - Bandwidth utilization percentage
    - Error rates (CRC, input/output errors)
    - Top interfaces by traffic

    Args:
        device_name: Specific device, or None for all devices
        top_n: Number of top interfaces to return per device

    Returns:
        str: JSON with interface report
    """
    devices_to_check = [device_name] if device_name else list(DEVICES.keys())

    for dev in devices_to_check:
        if dev not in DEVICES:
            return json.dumps({
                "status": "error",
                "error": f"Device '{dev}' not found. Available: {list(DEVICES.keys())}"
            }, indent=2)

    try:
        testbed = get_testbed()
        results = {
            "status": "success",
            "timestamp": datetime.now().isoformat(),
            "devices_checked": len(devices_to_check),
            "results": {},
            "summary": {
                "total_interfaces": 0,
                "interfaces_with_errors": 0,
                "interfaces_down": 0
            }
        }

        for dev_name in devices_to_check:
            device = testbed.devices[dev_name]
            device.connect(log_stdout=False)

            # Learn interface state using pyATS
            learned = device.learn("interface")

            device.disconnect()

            if not hasattr(learned, 'info'):
                results["results"][dev_name] = {"error": "Could not learn interface state"}
                continue

            interfaces = []
            for intf_name, intf_data in learned.info.items():
                # Skip non-physical interfaces for utilization
                if any(x in intf_name.lower() for x in ['loopback', 'null', 'tunnel', 'vlan', 'nve', 'bdi']):
                    continue

                intf_info = {
                    "name": intf_name,
                    "status": intf_data.get("oper_status", "unknown"),
                    "admin_status": intf_data.get("enabled", "unknown"),
                    "bandwidth_kbps": intf_data.get("bandwidth", 0),
                    "mtu": intf_data.get("mtu", 0),
                }

                # Get counters if available
                counters = intf_data.get("counters", {})
                if counters:
                    intf_info["in_pkts"] = counters.get("in_pkts", 0)
                    intf_info["out_pkts"] = counters.get("out_pkts", 0)
                    intf_info["in_octets"] = counters.get("in_octets", 0)
                    intf_info["out_octets"] = counters.get("out_octets", 0)
                    intf_info["in_errors"] = counters.get("in_errors", 0)
                    intf_info["out_errors"] = counters.get("out_errors", 0)
                    intf_info["in_crc_errors"] = counters.get("in_crc_errors", 0)

                    # Calculate total traffic for ranking
                    intf_info["total_octets"] = intf_info.get("in_octets", 0) + intf_info.get("out_octets", 0)
                    intf_info["total_errors"] = intf_info.get("in_errors", 0) + intf_info.get("out_errors", 0)

                    if intf_info["total_errors"] > 0:
                        results["summary"]["interfaces_with_errors"] += 1

                if intf_info["status"] == "down":
                    results["summary"]["interfaces_down"] += 1

                interfaces.append(intf_info)
                results["summary"]["total_interfaces"] += 1

            # Sort by total traffic (top talkers)
            interfaces.sort(key=lambda x: x.get("total_octets", 0), reverse=True)

            # Get interfaces with errors
            error_interfaces = [i for i in interfaces if i.get("total_errors", 0) > 0]

            results["results"][dev_name] = {
                "interface_count": len(interfaces),
                "top_by_traffic": interfaces[:top_n],
                "interfaces_with_errors": error_interfaces[:5],
                "down_interfaces": [i["name"] for i in interfaces if i["status"] == "down"]
            }

        return json.dumps(results, indent=2, default=str)

    except Exception as e:
        return json.dumps({
            "status": "error",
            "error": str(e)
        }, indent=2)


# =============================================================================
# Inventory Report (Fleet-wide version/hardware summary)
# =============================================================================

def inventory_report(device_name: str = None) -> str:
    """
    Generate fleet-wide hardware and software inventory report.

    Uses pyATS to learn platform information:
    - Software version
    - Hardware model
    - Serial numbers
    - Uptime
    - Memory/CPU utilization

    Args:
        device_name: Specific device, or None for all devices

    Returns:
        str: JSON with inventory report
    """
    devices_to_check = [device_name] if device_name else list(DEVICES.keys())

    for dev in devices_to_check:
        if dev not in DEVICES:
            return json.dumps({
                "status": "error",
                "error": f"Device '{dev}' not found. Available: {list(DEVICES.keys())}"
            }, indent=2)

    try:
        testbed = get_testbed()
        results = {
            "status": "success",
            "timestamp": datetime.now().isoformat(),
            "devices_inventoried": len(devices_to_check),
            "results": {},
            "summary": {
                "versions": {},
                "models": {},
                "total_memory_mb": 0,
                "oldest_uptime": None,
                "newest_uptime": None
            }
        }

        for dev_name in devices_to_check:
            device = testbed.devices[dev_name]
            device.connect(log_stdout=False)

            # Learn platform info using pyATS
            try:
                learned = device.learn("platform")
                platform_info = learned.info if hasattr(learned, 'info') else {}
            except Exception:
                platform_info = {}

            # Also get show version for additional details
            version_output = device.execute("show version")

            # Get inventory
            try:
                inventory_output = device.execute("show inventory")
            except Exception:
                inventory_output = ""

            device.disconnect()

            # Parse version details
            import re
            version_match = re.search(r'Version\s+([\d\.]+\w*)', version_output)
            version = version_match.group(1) if version_match else "unknown"

            model_match = re.search(r'cisco\s+(\S+)', version_output, re.IGNORECASE)
            model = model_match.group(1) if model_match else "unknown"

            uptime_match = re.search(r'uptime is\s+(.+)', version_output)
            uptime = uptime_match.group(1) if uptime_match else "unknown"

            serial_match = re.search(r'Processor board ID\s+(\S+)', version_output)
            serial = serial_match.group(1) if serial_match else "unknown"

            memory_match = re.search(r'(\d+)K/(\d+)K bytes of memory', version_output)
            memory_total = int(memory_match.group(1)) + int(memory_match.group(2)) if memory_match else 0
            memory_mb = memory_total // 1024

            # Parse inventory for modules
            modules = []
            for match in re.finditer(r'NAME:\s+"([^"]+)".*?DESCR:\s+"([^"]+)".*?SN:\s+(\S+)', inventory_output, re.DOTALL):
                modules.append({
                    "name": match.group(1),
                    "description": match.group(2),
                    "serial": match.group(3)
                })

            results["results"][dev_name] = {
                "version": version,
                "model": model,
                "serial_number": serial,
                "uptime": uptime,
                "memory_mb": memory_mb,
                "modules": modules[:5],  # Limit to first 5 modules
                "module_count": len(modules)
            }

            # Update summary
            results["summary"]["versions"][version] = results["summary"]["versions"].get(version, 0) + 1
            results["summary"]["models"][model] = results["summary"]["models"].get(model, 0) + 1
            results["summary"]["total_memory_mb"] += memory_mb

        return json.dumps(results, indent=2, default=str)

    except Exception as e:
        return json.dumps({
            "status": "error",
            "error": str(e)
        }, indent=2)


# MCP Tool registration helper
def register_pyats_tools(mcp):
    """
    Register all pyATS tools with the MCP server.

    Args:
        mcp: FastMCP instance to register tools with
    """

    @mcp.tool()
    def pyats_generate_testbed() -> str:
        """Generate pyATS testbed YAML from device inventory"""
        return generate_testbed()

    @mcp.tool()
    def pyats_learn_feature(device_name: str, feature: str) -> str:
        """Learn device feature state (ospf, eigrp, interface, routing, bgp, vrf, arp, platform)"""
        return learn_feature(device_name, feature)

    @mcp.tool()
    def pyats_snapshot_state(device_name: str, label: str = "baseline") -> str:
        """Capture device state to baseline file for later comparison"""
        return snapshot_state(device_name, label)

    @mcp.tool()
    def pyats_diff_state(device_name: str, label: str = "baseline") -> str:
        """Compare current device state against saved baseline"""
        return diff_state(device_name, label)

    @mcp.tool()
    def pyats_check_compliance(device_name: str, template: str = "default") -> str:
        """Check running config against golden template"""
        return check_compliance(device_name, template)

    @mcp.tool()
    def pyats_list_baselines() -> str:
        """List all saved baseline snapshots"""
        return list_baselines()

    @mcp.tool()
    def pyats_list_templates() -> str:
        """List available golden config templates"""
        return list_templates()


if __name__ == "__main__":
    # Test functions directly
    print("Testing pyATS tools...")
    print("\n=== Generate Testbed ===")
    print(generate_testbed())
