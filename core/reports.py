"""
Report Generation Module for NetworkOps.

Generates PDF and CSV reports from network data:
- Device inventory
- Health check results
- Configuration compliance
- Topology snapshots
- Security audit results

Uses ReportLab for PDF generation and standard csv module for CSV.
"""

import csv
import io
import json
import logging
from dataclasses import dataclass, field
from core.timestamps import now
from enum import Enum
from pathlib import Path
from typing import Optional, Any

logger = logging.getLogger(__name__)

# =============================================================================
# Report Types
# =============================================================================

class ReportType(str, Enum):
    """Available report types."""
    DEVICE_INVENTORY = "device_inventory"
    HEALTH_CHECK = "health_check"
    COMPLIANCE = "compliance"
    SECURITY_AUDIT = "security_audit"
    INTERFACE_STATUS = "interface_status"
    TOPOLOGY = "topology"
    BACKUP_HISTORY = "backup_history"
    JOB_HISTORY = "job_history"


class ReportFormat(str, Enum):
    """Supported export formats."""
    CSV = "csv"
    PDF = "pdf"
    JSON = "json"


@dataclass
class ReportMetadata:
    """Report metadata."""
    title: str
    report_type: str
    generated_at: str
    generated_by: str = "NetworkOps"
    row_count: int = 0
    filters: dict = field(default_factory=dict)


# =============================================================================
# CSV Generation
# =============================================================================

def generate_csv(data: list[dict], columns: list[str] = None) -> str:
    """
    Generate CSV string from list of dictionaries.

    Args:
        data: List of dictionaries to convert
        columns: Column order (optional, uses keys from first row if not specified)

    Returns:
        CSV string
    """
    if not data:
        return ""

    # Use provided columns or extract from first row
    if columns is None:
        columns = list(data[0].keys())

    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=columns, extrasaction='ignore')
    writer.writeheader()

    for row in data:
        # Flatten nested dicts/lists for CSV
        flat_row = {}
        for col in columns:
            value = row.get(col, "")
            if isinstance(value, (dict, list)):
                value = json.dumps(value)
            flat_row[col] = value
        writer.writerow(flat_row)

    return output.getvalue()


# =============================================================================
# PDF Generation (using ReportLab)
# =============================================================================

def generate_pdf(
    title: str,
    data: list[dict],
    columns: list[str] = None,
    column_widths: list[float] = None,
) -> bytes:
    """
    Generate PDF report from data.

    Args:
        title: Report title
        data: List of dictionaries
        columns: Column names to include
        column_widths: Optional column widths (percentages)

    Returns:
        PDF bytes
    """
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import letter, landscape
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import inch
        from reportlab.platypus import (
            SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
        )
    except ImportError:
        raise ImportError(
            "ReportLab is required for PDF generation. "
            "Install with: pip install reportlab"
        )

    if not data:
        # Return empty PDF with message
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter)
        styles = getSampleStyleSheet()
        elements = [
            Paragraph(title, styles['Title']),
            Spacer(1, 20),
            Paragraph("No data available for this report.", styles['Normal'])
        ]
        doc.build(elements)
        return buffer.getvalue()

    # Use provided columns or extract from first row
    if columns is None:
        columns = list(data[0].keys())

    # Prepare table data
    table_data = [columns]  # Header row
    for row in data:
        row_values = []
        for col in columns:
            value = row.get(col, "")
            if isinstance(value, (dict, list)):
                value = json.dumps(value)[:50] + "..." if len(json.dumps(value)) > 50 else json.dumps(value)
            elif value is None:
                value = ""
            else:
                value = str(value)[:100]  # Truncate long strings
            row_values.append(value)
        table_data.append(row_values)

    # Create PDF
    buffer = io.BytesIO()

    # Use landscape if many columns
    if len(columns) > 6:
        doc = SimpleDocTemplate(buffer, pagesize=landscape(letter))
    else:
        doc = SimpleDocTemplate(buffer, pagesize=letter)

    styles = getSampleStyleSheet()
    elements = []

    # Title
    elements.append(Paragraph(title, styles['Title']))
    elements.append(Spacer(1, 12))

    # Timestamp
    timestamp = now().strftime("%Y-%m-%d %H:%M:%S UTC")
    elements.append(Paragraph(f"Generated: {timestamp}", styles['Normal']))
    elements.append(Paragraph(f"Total Records: {len(data)}", styles['Normal']))
    elements.append(Spacer(1, 20))

    # Table
    table = Table(table_data)

    # Table styling
    table.setStyle(TableStyle([
        # Header styling
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2c3e50')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 10),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('TOPPADDING', (0, 0), (-1, 0), 12),

        # Data rows styling
        ('BACKGROUND', (0, 1), (-1, -1), colors.white),
        ('TEXTCOLOR', (0, 1), (-1, -1), colors.black),
        ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
        ('FONTSIZE', (0, 1), (-1, -1), 8),
        ('BOTTOMPADDING', (0, 1), (-1, -1), 8),
        ('TOPPADDING', (0, 1), (-1, -1), 8),

        # Alternating row colors
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f5f6fa')]),

        # Grid
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#dcdde1')),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
    ]))

    elements.append(table)

    # Footer
    elements.append(Spacer(1, 20))
    elements.append(Paragraph(
        "Generated by NetworkOps - AI-Powered Network Automation",
        styles['Italic']
    ))

    doc.build(elements)
    return buffer.getvalue()


# =============================================================================
# Report Generators
# =============================================================================

async def generate_device_inventory_report(format: str = "csv") -> tuple[str | bytes, str]:
    """
    Generate device inventory report.

    Returns:
        Tuple of (content, filename)
    """
    from config.devices import DEVICES, is_cisco_device

    data = []
    for name, device in DEVICES.items():
        data.append({
            "device_name": name,
            "host": device.get("host", ""),
            "device_type": device.get("device_type", ""),
            "is_cisco": is_cisco_device(name),
            "platform": device.get("platform", ""),
        })

    columns = ["device_name", "host", "device_type", "is_cisco", "platform"]
    timestamp = now().strftime("%Y%m%d_%H%M%S")

    if format == "csv":
        content = generate_csv(data, columns)
        filename = f"device_inventory_{timestamp}.csv"
    elif format == "pdf":
        content = generate_pdf("Device Inventory Report", data, columns)
        filename = f"device_inventory_{timestamp}.pdf"
    else:  # json
        content = json.dumps({"report_type": "device_inventory", "data": data}, indent=2)
        filename = f"device_inventory_{timestamp}.json"

    return content, filename


async def generate_health_report(results: dict, format: str = "csv") -> tuple[str | bytes, str]:
    """
    Generate health check report from health_check_all results.

    Args:
        results: Output from health_check_all

    Returns:
        Tuple of (content, filename)
    """
    devices = results.get("devices", [])

    data = []
    for device in devices:
        data.append({
            "device": device.get("device", ""),
            "status": device.get("status", "unknown"),
            "interface_count": device.get("interface_count", 0),
            "interfaces_up": device.get("interfaces_up", 0),
            "interfaces_down": device.get("interfaces_down", 0),
            "error": device.get("error", ""),
            "from_cache": device.get("_from_cache", False),
        })

    columns = ["device", "status", "interface_count", "interfaces_up", "interfaces_down", "error"]
    timestamp = now().strftime("%Y%m%d_%H%M%S")

    if format == "csv":
        content = generate_csv(data, columns)
        filename = f"health_report_{timestamp}.csv"
    elif format == "pdf":
        content = generate_pdf("Network Health Report", data, columns)
        filename = f"health_report_{timestamp}.pdf"
    else:
        content = json.dumps({"report_type": "health_check", "summary": results.get("summary"), "data": data}, indent=2)
        filename = f"health_report_{timestamp}.json"

    return content, filename


async def generate_security_audit_report(results: dict, format: str = "csv") -> tuple[str | bytes, str]:
    """
    Generate security audit report from pyats_security_audit results.

    Args:
        results: Output from pyats_security_audit

    Returns:
        Tuple of (content, filename)
    """
    devices = results.get("devices", [])

    data = []
    for device in devices:
        device_name = device.get("device", "")
        score = device.get("score", 0)
        issues = device.get("issues", [])

        if not issues:
            data.append({
                "device": device_name,
                "score": score,
                "issue": "No issues found",
                "severity": "info",
                "recommendation": "-"
            })
        else:
            for issue in issues:
                data.append({
                    "device": device_name,
                    "score": score,
                    "issue": issue.get("issue", ""),
                    "severity": issue.get("severity", ""),
                    "recommendation": issue.get("recommendation", "")
                })

    columns = ["device", "score", "severity", "issue", "recommendation"]
    timestamp = now().strftime("%Y%m%d_%H%M%S")

    if format == "csv":
        content = generate_csv(data, columns)
        filename = f"security_audit_{timestamp}.csv"
    elif format == "pdf":
        content = generate_pdf("Security Audit Report", data, columns)
        filename = f"security_audit_{timestamp}.pdf"
    else:
        content = json.dumps({"report_type": "security_audit", "data": data}, indent=2)
        filename = f"security_audit_{timestamp}.json"

    return content, filename


async def generate_interface_report(results: dict, format: str = "csv") -> tuple[str | bytes, str]:
    """
    Generate interface status report from pyats_interface_report results.

    Args:
        results: Output from pyats_interface_report

    Returns:
        Tuple of (content, filename)
    """
    devices = results.get("devices", [])

    data = []
    for device in devices:
        device_name = device.get("device", "")
        interfaces = device.get("interfaces", [])

        for intf in interfaces:
            data.append({
                "device": device_name,
                "interface": intf.get("interface", ""),
                "admin_status": intf.get("admin_status", ""),
                "oper_status": intf.get("oper_status", ""),
                "in_rate_kbps": intf.get("in_rate_kbps", 0),
                "out_rate_kbps": intf.get("out_rate_kbps", 0),
                "in_errors": intf.get("in_errors", 0),
                "out_errors": intf.get("out_errors", 0),
            })

    columns = ["device", "interface", "admin_status", "oper_status", "in_rate_kbps", "out_rate_kbps", "in_errors", "out_errors"]
    timestamp = now().strftime("%Y%m%d_%H%M%S")

    if format == "csv":
        content = generate_csv(data, columns)
        filename = f"interface_report_{timestamp}.csv"
    elif format == "pdf":
        content = generate_pdf("Interface Status Report", data, columns)
        filename = f"interface_report_{timestamp}.pdf"
    else:
        content = json.dumps({"report_type": "interface_status", "data": data}, indent=2)
        filename = f"interface_report_{timestamp}.json"

    return content, filename


async def generate_compliance_report(results: list[dict], format: str = "csv") -> tuple[str | bytes, str]:
    """
    Generate compliance report from compliance check results.

    Args:
        results: List of compliance check results per device

    Returns:
        Tuple of (content, filename)
    """
    data = []
    for result in results:
        device = result.get("device", "")
        compliant = result.get("compliant", False)
        issues = result.get("issues", [])

        if not issues:
            data.append({
                "device": device,
                "compliant": compliant,
                "rule": "-",
                "expected": "-",
                "actual": "-",
            })
        else:
            for issue in issues:
                data.append({
                    "device": device,
                    "compliant": compliant,
                    "rule": issue.get("rule", ""),
                    "expected": issue.get("expected", ""),
                    "actual": issue.get("actual", ""),
                })

    columns = ["device", "compliant", "rule", "expected", "actual"]
    timestamp = now().strftime("%Y%m%d_%H%M%S")

    if format == "csv":
        content = generate_csv(data, columns)
        filename = f"compliance_report_{timestamp}.csv"
    elif format == "pdf":
        content = generate_pdf("Configuration Compliance Report", data, columns)
        filename = f"compliance_report_{timestamp}.pdf"
    else:
        content = json.dumps({"report_type": "compliance", "data": data}, indent=2)
        filename = f"compliance_report_{timestamp}.json"

    return content, filename


async def generate_topology_report(topology: dict, format: str = "csv") -> tuple[str | bytes, str]:
    """
    Generate topology report from discover_topology results.

    Args:
        topology: Output from discover_topology

    Returns:
        Tuple of (content, filename)
    """
    nodes = topology.get("nodes", [])
    links = topology.get("links", [])

    # Nodes table
    node_data = []
    for node in nodes:
        node_data.append({
            "id": node.get("id", ""),
            "ip": node.get("ip", ""),
            "platform": node.get("platform", ""),
            "status": node.get("status", ""),
        })

    # Links table
    link_data = []
    for link in links:
        link_data.append({
            "source": link.get("source", ""),
            "target": link.get("target", ""),
            "source_intf": link.get("source_intf", ""),
            "target_intf": link.get("target_intf", ""),
        })

    timestamp = now().strftime("%Y%m%d_%H%M%S")

    if format == "csv":
        # Combine nodes and links
        content = "# Nodes\n" + generate_csv(node_data) + "\n# Links\n" + generate_csv(link_data)
        filename = f"topology_{timestamp}.csv"
    elif format == "pdf":
        # For PDF, we'll make two tables
        try:
            from reportlab.platypus import PageBreak
            from reportlab.lib.pagesizes import letter
            from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
            from reportlab.lib.styles import getSampleStyleSheet
            from reportlab.lib import colors

            buffer = io.BytesIO()
            doc = SimpleDocTemplate(buffer, pagesize=letter)
            styles = getSampleStyleSheet()
            elements = []

            # Title
            elements.append(Paragraph("Network Topology Report", styles['Title']))
            elements.append(Spacer(1, 20))

            # Nodes section
            elements.append(Paragraph("Nodes", styles['Heading2']))
            if node_data:
                node_table_data = [["ID", "IP", "Platform", "Status"]]
                for node in node_data:
                    node_table_data.append([node["id"], node["ip"], node["platform"], node["status"]])
                node_table = Table(node_table_data)
                node_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2c3e50')),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                ]))
                elements.append(node_table)

            elements.append(Spacer(1, 20))

            # Links section
            elements.append(Paragraph("Links", styles['Heading2']))
            if link_data:
                link_table_data = [["Source", "Target", "Source Interface", "Target Interface"]]
                for link in link_data:
                    link_table_data.append([link["source"], link["target"], link["source_intf"], link["target_intf"]])
                link_table = Table(link_table_data)
                link_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2c3e50')),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                ]))
                elements.append(link_table)

            doc.build(elements)
            content = buffer.getvalue()
        except ImportError:
            # Fall back to JSON if ReportLab not available
            content = json.dumps(topology, indent=2).encode()
        filename = f"topology_{timestamp}.pdf"
    else:
        content = json.dumps({"report_type": "topology", "nodes": node_data, "links": link_data}, indent=2)
        filename = f"topology_{timestamp}.json"

    return content, filename


async def generate_backup_history_report(backups: list[dict], format: str = "csv") -> tuple[str | bytes, str]:
    """
    Generate backup history report from list_backups results.

    Args:
        backups: List of backup metadata

    Returns:
        Tuple of (content, filename)
    """
    data = []
    for backup in backups:
        data.append({
            "device": backup.get("device", ""),
            "filename": backup.get("filename", ""),
            "timestamp": backup.get("timestamp", ""),
            "size_bytes": backup.get("size_bytes", 0),
            "label": backup.get("label", ""),
        })

    columns = ["device", "filename", "timestamp", "size_bytes", "label"]
    timestamp = now().strftime("%Y%m%d_%H%M%S")

    if format == "csv":
        content = generate_csv(data, columns)
        filename = f"backup_history_{timestamp}.csv"
    elif format == "pdf":
        content = generate_pdf("Configuration Backup History", data, columns)
        filename = f"backup_history_{timestamp}.pdf"
    else:
        content = json.dumps({"report_type": "backup_history", "data": data}, indent=2)
        filename = f"backup_history_{timestamp}.json"

    return content, filename


# =============================================================================
# Public API
# =============================================================================

async def get_supported_report_types() -> list[dict]:
    """Get list of supported report types."""
    return [
        {"type": "device_inventory", "description": "List of all devices with connection details"},
        {"type": "health_check", "description": "Device health status and interface counts"},
        {"type": "security_audit", "description": "Security audit findings and recommendations"},
        {"type": "interface_status", "description": "Interface status, traffic rates, and errors"},
        {"type": "compliance", "description": "Configuration compliance check results"},
        {"type": "topology", "description": "Network topology nodes and links"},
        {"type": "backup_history", "description": "Configuration backup history"},
    ]


async def get_supported_formats() -> list[str]:
    """Get list of supported export formats."""
    return ["csv", "pdf", "json"]
