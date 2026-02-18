"""
Alerts API Route.

Receives webhook alerts from Prometheus AlertManager and logs them.
"""

import json
import logging
from datetime import datetime, timezone
from pathlib import Path

from flask import Blueprint, jsonify, request

logger = logging.getLogger(__name__)

alerts_bp = Blueprint('alerts', __name__)

ALERTS_LOG = Path(__file__).parent.parent.parent / "data" / "alerts.json"


def _load_alerts():
    """Load existing alerts from disk."""
    if not ALERTS_LOG.exists():
        return []
    try:
        with open(ALERTS_LOG, 'r') as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return []


def _save_alerts(alerts):
    """Persist alerts to disk."""
    ALERTS_LOG.parent.mkdir(parents=True, exist_ok=True)
    with open(ALERTS_LOG, 'w') as f:
        json.dump(alerts, f, indent=2)


@alerts_bp.route('/api/alerts/webhook', methods=['POST'])
def alertmanager_webhook():
    """Receive alerts from Prometheus AlertManager.

    AlertManager sends a JSON payload with grouped alerts.
    See: https://prometheus.io/docs/alerting/latest/configuration/#webhook_config
    """
    payload = request.get_json(silent=True)
    if not payload:
        return jsonify({"error": "Invalid JSON payload"}), 400

    received_at = datetime.now(timezone.utc).isoformat()
    alert_records = []

    for alert in payload.get("alerts", []):
        record = {
            "status": alert.get("status"),
            "alertname": alert.get("labels", {}).get("alertname"),
            "severity": alert.get("labels", {}).get("severity"),
            "device": alert.get("labels", {}).get("device"),
            "summary": alert.get("annotations", {}).get("summary"),
            "description": alert.get("annotations", {}).get("description"),
            "starts_at": alert.get("startsAt"),
            "ends_at": alert.get("endsAt"),
            "received_at": received_at,
        }
        alert_records.append(record)

    if alert_records:
        existing = _load_alerts()
        existing.extend(alert_records)
        # Keep last 1000 alerts
        if len(existing) > 1000:
            existing = existing[-1000:]
        _save_alerts(existing)

    logger.info("Received %d alerts from AlertManager (status: %s)",
                len(alert_records), payload.get("status"))

    return jsonify({"status": "ok", "received": len(alert_records)})


@alerts_bp.route('/api/alerts')
def get_alerts():
    """Get recent alerts."""
    limit = request.args.get('limit', 50, type=int)
    severity = request.args.get('severity', None)
    status = request.args.get('status', None)

    alerts = _load_alerts()
    alerts = list(reversed(alerts))

    if severity:
        alerts = [a for a in alerts if a.get("severity") == severity]
    if status:
        alerts = [a for a in alerts if a.get("status") == status]

    alerts = alerts[:limit]

    return jsonify({
        "total_alerts": len(alerts),
        "alerts": alerts,
    })
