"""
Reporting MCP tools.

This module provides tools for generating reports:
- report_generate: Generate reports in PDF, CSV, or JSON format
- report_types: List available report types and formats

Note: Convenience wrappers (report_device_inventory, report_health, report_topology)
removed - use report_generate() directly with the appropriate report_type parameter.
"""

import base64
import json

from core.reports import (
    generate_device_inventory_report,
    generate_health_report,
    generate_security_audit_report,
    generate_interface_report,
    generate_topology_report,
    generate_backup_history_report,
    get_supported_report_types,
    get_supported_formats,
)


# =============================================================================
# MCP Tool Functions
# =============================================================================

async def report_generate(report_type: str, format: str = "csv") -> str:
    """
    Generate a report in PDF, CSV, or JSON format.

    Args:
        report_type: Type of report. Options:
            - device_inventory: List of all devices with connection details
            - health_check: Current device health status (runs health check)
            - security_audit: Security findings (runs security audit)
            - interface_status: Interface traffic and errors (runs interface report)
            - topology: Network topology nodes and links (runs discovery)
            - backup_history: Configuration backup history
        format: Output format - "csv", "pdf", or "json" (default: csv)

    Returns:
        For CSV/JSON: String content
        For PDF: Base64-encoded PDF with filename

    Examples:
        # Get device inventory as CSV
        report_generate("device_inventory", "csv")

        # Get health report as PDF
        report_generate("health_check", "pdf")

        # Get topology as JSON
        report_generate("topology", "json")
    """
    valid_types = ["device_inventory", "health_check", "security_audit",
                   "interface_status", "topology", "backup_history"]
    valid_formats = ["csv", "pdf", "json"]

    if report_type not in valid_types:
        return json.dumps({"error": f"Invalid report type. Options: {valid_types}"})

    if format not in valid_formats:
        return json.dumps({"error": f"Invalid format. Options: {valid_formats}"})

    try:
        if report_type == "device_inventory":
            content, filename = await generate_device_inventory_report(format)

        elif report_type == "health_check":
            # Import here to avoid circular dependency
            from mcp_tools.device import health_check_all
            result = await health_check_all()
            health_data = json.loads(result)
            content, filename = await generate_health_report(health_data, format)

        elif report_type == "security_audit":
            # Import here to avoid circular dependency
            from mcp_tools.compliance import compliance_check_all
            result = await compliance_check_all(template="security-baseline")
            audit_data = json.loads(result)
            content, filename = await generate_security_audit_report(audit_data, format)

        elif report_type == "interface_status":
            # Import here to avoid circular dependency
            from mcp_tools.testing import pyats_interface_report
            result = await pyats_interface_report()
            interface_data = json.loads(result)
            content, filename = await generate_interface_report(interface_data, format)

        elif report_type == "topology":
            # Import here to avoid circular dependency
            from mcp_tools.topology import discover_topology
            result = await discover_topology()
            topology_data = json.loads(result)
            content, filename = await generate_topology_report(topology_data, format)

        elif report_type == "backup_history":
            # Import here to avoid circular dependency
            from mcp_tools.config import list_backups
            result = await list_backups()
            backup_data = json.loads(result)
            content, filename = await generate_backup_history_report(
                backup_data.get("backups", []), format
            )

        # Return result
        if format == "pdf":
            # Encode PDF as base64 for transport
            return json.dumps({
                "success": True,
                "filename": filename,
                "format": "pdf",
                "content_base64": base64.b64encode(content).decode('utf-8'),
                "size_bytes": len(content)
            }, indent=2)
        else:
            return json.dumps({
                "success": True,
                "filename": filename,
                "format": format,
                "content": content
            }, indent=2)

    except Exception as e:
        return json.dumps({"error": str(e)})


async def report_types() -> str:
    """
    Get list of available report types and formats.

    Returns:
        JSON with supported report types and export formats
    """
    types = await get_supported_report_types()
    formats = await get_supported_formats()

    return json.dumps({
        "report_types": types,
        "formats": formats,
        "usage": "report_generate(report_type, format)"
    }, indent=2)


# =============================================================================
# Tool Registry
# =============================================================================

TOOLS = [
    {"fn": report_generate, "name": "report_generate", "category": "reporting"},
    {"fn": report_types, "name": "report_types", "category": "reporting"},
]
