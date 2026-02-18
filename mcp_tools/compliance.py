"""
Compliance MCP tools.

This module provides tools for configuration compliance:
- compliance_check: Check device against template
- compliance_check_all: Check multiple devices
- compliance_list_templates: List available templates
- compliance_get_template: Get template details
- compliance_history: Get compliance history
- compliance_trend: Get compliance trend
- compliance_remediate: Generate/apply remediation
"""

import json

from core import log_event


# =============================================================================
# MCP Tool Functions
# =============================================================================

async def compliance_check(
    device_name: str,
    template: str = "security-baseline",
) -> str:
    """
    Check device configuration compliance against a template.

    Performs section-based configuration analysis with weighted scoring.
    Returns violations, compliance score, and auto-generated remediation commands.

    Args:
        device_name: Device to check (e.g., "R1")
        template: Template name (default: "security-baseline")
                  Available: security-baseline, operational-baseline

    Returns:
        JSON with compliance score (0-100), status, violations, and remediation

    Examples:
        compliance_check("R1")
        compliance_check("R1", "operational-baseline")
    """
    from core.compliance_engine import get_compliance_engine

    try:
        engine = get_compliance_engine()
        result = await engine.check_compliance(device_name, template)

        log_event("compliance_check", device_name, f"Score: {result.score:.1f}%, Template: {template}",
                  "success" if result.status.value != "error" else "error", "operator")

        return json.dumps(result.to_dict(), indent=2)
    except Exception as e:
        return json.dumps({"error": str(e), "device": device_name}, indent=2)


async def compliance_check_all(
    template: str = "security-baseline",
    devices: str = "",
) -> str:
    """
    Check compliance for multiple devices in parallel.

    Args:
        template: Template name (default: "security-baseline")
        devices: Comma-separated device names (empty = all Cisco devices)

    Returns:
        JSON with summary and per-device compliance results

    Examples:
        compliance_check_all()
        compliance_check_all("security-baseline", "R1,R2,R3,R4")
    """
    from core.compliance_engine import get_compliance_engine

    try:
        engine = get_compliance_engine()

        device_names = None
        if devices:
            device_names = [d.strip() for d in devices.split(",")]

        results = await engine.check_all_devices(template, device_names)

        summary = {
            "total": len(results),
            "compliant": sum(1 for r in results if r.status.value == "compliant"),
            "partial": sum(1 for r in results if r.status.value == "partial"),
            "non_compliant": sum(1 for r in results if r.status.value == "non_compliant"),
            "error": sum(1 for r in results if r.status.value == "error"),
            "average_score": sum(r.score for r in results) / len(results) if results else 0,
        }

        log_event("compliance_check_all", "all",
                  f"Checked {summary['total']} devices, avg score: {summary['average_score']:.1f}%",
                  "success", "operator")

        return json.dumps({
            "summary": summary,
            "template": template,
            "results": [r.to_dict() for r in results],
        }, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)}, indent=2)


async def compliance_list_templates() -> str:
    """
    List available compliance templates.

    Returns:
        JSON with template names, descriptions, and rule counts
    """
    from core.compliance_engine import get_compliance_engine

    try:
        engine = get_compliance_engine()
        templates = engine.list_templates()
        return json.dumps({"templates": templates}, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)}, indent=2)


async def compliance_get_template(template_name: str) -> str:
    """
    Get details of a specific compliance template including all rules.

    Args:
        template_name: Template name (e.g., "security-baseline")

    Returns:
        JSON with template details and all rules
    """
    from core.compliance_engine import get_compliance_engine

    try:
        engine = get_compliance_engine()
        template = engine.get_template(template_name)

        if not template:
            return json.dumps({"error": f"Template '{template_name}' not found"})

        return json.dumps(template.to_dict(), indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)}, indent=2)


async def compliance_history(
    device_name: str = "",
    days: int = 30,
    template: str = "",
) -> str:
    """
    Get compliance check history.

    Args:
        device_name: Filter by device (empty = all devices)
        days: Number of days to look back (default: 30)
        template: Filter by template (empty = all templates)

    Returns:
        JSON with historical compliance records
    """
    from core.compliance_engine import get_compliance_engine

    try:
        engine = get_compliance_engine()
        history = engine.get_compliance_history(
            device_name or None,
            days,
            template or None,
        )
        return json.dumps({
            "count": len(history),
            "days": days,
            "device_filter": device_name or "all",
            "template_filter": template or "all",
            "history": history,
        }, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)}, indent=2)


async def compliance_trend(
    device_name: str,
    days: int = 30,
    template: str = "security-baseline",
) -> str:
    """
    Get compliance score trend for a device.

    Shows how compliance has changed over time, useful for tracking
    improvement or detecting drift.

    Args:
        device_name: Device to analyze
        days: Number of days to look back (default: 30)
        template: Template to track (default: "security-baseline")

    Returns:
        JSON with trend data and direction (improving/declining/stable)
    """
    from core.compliance_engine import get_compliance_engine

    try:
        engine = get_compliance_engine()
        trend = engine.get_compliance_trend(device_name, days, template)
        return json.dumps(trend, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e), "device": device_name}, indent=2)


async def compliance_remediate(
    device_name: str,
    template: str = "security-baseline",
    dry_run: bool = True,
) -> str:
    """
    Generate or apply remediation commands for compliance violations.

    Args:
        device_name: Device to remediate
        template: Template to check against
        dry_run: If True (default), only show commands without applying

    Returns:
        JSON with remediation commands and apply status
    """
    from core.compliance_engine import get_compliance_engine

    try:
        engine = get_compliance_engine()
        result = await engine.check_compliance(device_name, template)

        if result.status.value == "error":
            return json.dumps({"error": result.error, "device": device_name}, indent=2)

        if not result.remediation_commands:
            return json.dumps({
                "device": device_name,
                "status": "compliant",
                "message": "No remediation needed",
                "score": result.score,
            }, indent=2)

        response = {
            "device": device_name,
            "template": template,
            "current_score": result.score,
            "violations_count": len(result.violations),
            "remediation_commands": result.remediation_commands,
            "dry_run": dry_run,
        }

        if not dry_run:
            # Apply remediation
            from config.devices import DEVICES
            from core.scrapli_manager import get_ios_xe_connection

            if device_name not in DEVICES:
                return json.dumps({"error": f"Device '{device_name}' not found"}, indent=2)

            try:
                async with get_ios_xe_connection(device_name) as conn:
                    # Send config commands
                    config_result = await conn.send_configs(result.remediation_commands)
                    response["applied"] = True
                    response["apply_result"] = config_result.result

                    log_event("compliance_remediate", device_name,
                              f"Applied {len(result.remediation_commands)} remediation commands",
                              "success", "admin")

            except Exception as e:
                response["applied"] = False
                response["apply_error"] = str(e)
        else:
            response["message"] = "Dry run - commands not applied. Set dry_run=False to apply."

        return json.dumps(response, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e), "device": device_name}, indent=2)


# =============================================================================
# Tool Registry
# =============================================================================

TOOLS = [
    {"fn": compliance_check, "name": "compliance_check", "category": "compliance"},
    {"fn": compliance_check_all, "name": "compliance_check_all", "category": "compliance"},
    {"fn": compliance_list_templates, "name": "compliance_list_templates", "category": "compliance"},
    {"fn": compliance_get_template, "name": "compliance_get_template", "category": "compliance"},
    {"fn": compliance_history, "name": "compliance_history", "category": "compliance"},
    {"fn": compliance_trend, "name": "compliance_trend", "category": "compliance"},
    {"fn": compliance_remediate, "name": "compliance_remediate", "category": "compliance"},
]
