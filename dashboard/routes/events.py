"""
Events API Route.

Event log endpoint extracted from api_server.py lines 1149-1178.
"""

import json
import logging
from pathlib import Path

from flask import Blueprint, jsonify, request
from dashboard.auth import jwt_required

logger = logging.getLogger(__name__)

events_bp = Blueprint('events', __name__)


@events_bp.route('/api/events')
@jwt_required
def get_events():
    """Get event log with optional filtering."""
    limit = request.args.get('limit', 50, type=int)
    device = request.args.get('device', None)
    action = request.args.get('action', None)

    event_log_file = Path(__file__).parent.parent.parent / "data" / "event_log.json"

    if not event_log_file.exists():
        return jsonify({"total_events": 0, "events": []})

    try:
        with open(event_log_file, 'r') as f:
            events = json.load(f)
    except Exception:
        return jsonify({"total_events": 0, "events": []})

    events = list(reversed(events))

    if device:
        events = [e for e in events if e.get("device") == device]
    if action:
        events = [e for e in events if e.get("action") == action]

    events = events[:limit]

    return jsonify({
        "total_events": len(events),
        "events": events
    })
