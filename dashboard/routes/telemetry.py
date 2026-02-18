"""
Telemetry API Routes.

MDT (Model-Driven Telemetry) collector control and data ingestion endpoints.
"""

import logging

from flask import Blueprint, jsonify, request
from core.errors import safe_error_response, ValidationError
from dashboard.auth import jwt_required, admin_required

logger = logging.getLogger(__name__)

telemetry_bp = Blueprint('telemetry', __name__, url_prefix='/api/telemetry')


def _get_collector():
    """Get the MDT collector singleton from api_server."""
    from dashboard.api_server import mdt_collector
    return mdt_collector


def _get_telemetry_data():
    """Get the telemetry data store from api_server."""
    from dashboard.api_server import telemetry_data
    return telemetry_data


def _get_ip_map():
    """Get the IP-to-device name map from api_server."""
    from dashboard.api_server import TELEMETRY_IP_MAP
    return TELEMETRY_IP_MAP


@telemetry_bp.route('/start', methods=['POST'])
@admin_required
def start_mdt_collector():
    """Start the MDT telemetry collector."""
    try:
        collector = _get_collector()
        success = collector.start()
        return jsonify({
            "status": "success" if success else "error",
            "message": "MDT collector started" if success else "Failed to start collector",
            "stats": collector.get_stats()
        })
    except Exception as e:
        return safe_error_response(e, "start MDT collector")


@telemetry_bp.route('/stop', methods=['POST'])
@admin_required
def stop_mdt_collector():
    """Stop the MDT telemetry collector."""
    try:
        collector = _get_collector()
        collector.stop()
        return jsonify({
            "status": "success",
            "message": "MDT collector stopped"
        })
    except Exception as e:
        return safe_error_response(e, "stop MDT collector")


@telemetry_bp.route('/stats')
@jwt_required
def get_mdt_stats():
    """Get MDT collector statistics."""
    try:
        collector = _get_collector()
        return jsonify({
            "collector": collector.get_stats(),
            "status": "success"
        })
    except Exception as e:
        return safe_error_response(e, "get MDT stats")


@telemetry_bp.route('/data')
@jwt_required
def get_telemetry_data():
    """Get telemetry data for a device or all devices."""
    try:
        tel_data = _get_telemetry_data()
        device = request.args.get('device')
        if device:
            data = tel_data.get_device_stats(device)
        else:
            data = tel_data.get_all_stats()
        return jsonify({
            "telemetry": data,
            "status": "success"
        })
    except Exception as e:
        return safe_error_response(e, "get telemetry data")


@telemetry_bp.route('/ingest', methods=['POST'])
@jwt_required
def ingest_telemetry():
    """
    Ingest telemetry data from external collectors (Telegraf, gNMIc, etc.).

    Accepts metrics in the following format:
    {
        "metrics": [
            {
                "name": "cpu_usage",
                "tags": {"source": "10.255.255.11"},
                "fields": {"five_seconds": 12.5},
                "timestamp": 1234567890
            }
        ]
    }
    """
    try:
        tel_data = _get_telemetry_data()
        ip_map = _get_ip_map()

        data = request.get_json()
        if not data:
            raise ValidationError("No data provided")

        metrics = data.get('metrics', [data] if isinstance(data, dict) else data)

        for metric in metrics:
            tags = metric.get('tags', {})
            source = tags.get('source', tags.get('host', ''))

            device = ip_map.get(source, source)
            if not device:
                continue

            name = metric.get('name', '')
            fields = metric.get('fields', {})

            if 'cpu' in name.lower() or 'five_seconds' in str(fields):
                cpu_val = fields.get('five_seconds', fields.get('cpu_util', 0))
                if cpu_val:
                    tel_data.update_cpu_stats(device, float(cpu_val))

            elif 'memory' in name.lower():
                pool_name = (tags.get('name', '') or
                             tags.get('memory_pool', '') or
                             tags.get('pool', ''))

                if pool_name and pool_name.lower() not in ['processor', '']:
                    continue

                used = (fields.get('used_memory', 0) or
                        fields.get('used-memory', 0) or
                        fields.get('used', 0) or
                        fields.get('memory_used', 0) or
                        fields.get('used_number', 0) or
                        fields.get('used-number', 0))
                free = (fields.get('free_memory', 0) or
                        fields.get('free-memory', 0) or
                        fields.get('free', 0) or
                        fields.get('memory_free', 0) or
                        fields.get('free_number', 0) or
                        fields.get('free-number', 0))
                total = (fields.get('total_memory', 0) or
                         fields.get('total-memory', 0) or
                         fields.get('total', 0) or
                         fields.get('memory_total', 0))

                if total and not (used and free):
                    if used:
                        free = total - used
                    elif free:
                        used = total - free

                min_pool_size = 50 * 1024 * 1024
                computed_total = used + free if (used or free) else total
                if computed_total > min_pool_size:
                    tel_data.update_memory_stats(device, int(used), int(free))

            elif 'interface' in name.lower() or 'statistics' in name.lower():
                intf_name = tags.get('name', tags.get('interface', 'unknown'))
                tel_data.update_interface_stats(device, intf_name, {
                    'in_octets': fields.get('in_octets', fields.get('in_broadcast_pkts', 0)),
                    'out_octets': fields.get('out_octets', fields.get('out_broadcast_pkts', 0)),
                    'in_packets': fields.get('in_pkts', fields.get('in_unicast_pkts', 0)),
                    'out_packets': fields.get('out_pkts', fields.get('out_unicast_pkts', 0)),
                    'in_errors': fields.get('in_errors', 0),
                    'out_errors': fields.get('out_errors', 0),
                })

        return jsonify({"status": "success", "processed": len(metrics)})

    except ValidationError:
        raise
    except Exception as e:
        return safe_error_response(e, "ingest telemetry data")
