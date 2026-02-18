"""
WebSocket event handlers for real-time telemetry.

Extracted from api_server.py lines 1230-1311.
"""

import logging

from flask import Blueprint
from flask_socketio import emit

from dashboard.auth.tokens import decode_token

logger = logging.getLogger(__name__)

websocket_bp = Blueprint('websocket', __name__)


def register_websocket_handlers(socketio_instance, telemetry_data):
    """Register SocketIO event handlers.

    Args:
        socketio_instance: Flask-SocketIO instance
        telemetry_data: Telemetry store for initial data
    """
    @socketio_instance.on('connect')
    def handle_connect(auth=None):
        # Require a valid JWT token from the auth dict
        if not auth or not isinstance(auth, dict):
            logger.warning("WebSocket connect rejected: no auth data")
            return False

        token = auth.get("token")
        if not token:
            logger.warning("WebSocket connect rejected: no token in auth")
            return False

        payload = decode_token(token)
        if not payload:
            logger.warning("WebSocket connect rejected: invalid/expired token")
            return False

        logger.debug(f"WebSocket client connected: {payload.get('sub')}")
        emit('connected', {'status': 'connected', 'message': 'Connected to telemetry stream'})

    @socketio_instance.on('disconnect')
    def handle_disconnect():
        logger.debug("WebSocket client disconnected")

    @socketio_instance.on('subscribe_telemetry')
    def handle_subscribe(data):
        devices = data.get('devices', [])
        logger.debug(f"Client subscribing to telemetry for: {devices}")

        if devices:
            for device in devices:
                device_data = telemetry_data.get_device_stats(device)
                emit('telemetry_update', {
                    'device': device,
                    'data': device_data,
                    'type': 'initial'
                })
        else:
            all_data = telemetry_data.get_all_stats()
            emit('telemetry_update', {
                'device': 'all',
                'data': all_data,
                'type': 'initial'
            })


def setup_telemetry_callbacks(socketio_instance, telemetry_data):
    """Set up telemetry data -> WebSocket broadcast callbacks.

    Args:
        socketio_instance: Flask-SocketIO instance
        telemetry_data: Telemetry store to subscribe to
    """
    from config.devices import DEVICES
    from core.topology_helpers import get_active_interfaces

    def broadcast_telemetry_update(message):
        socketio_instance.emit('telemetry_update', message)

    def broadcast_device_status_change(message):
        if message.get('type') != 'state_change':
            return

        device_name = message.get('device')
        if not device_name:
            return

        device = DEVICES.get(device_name)
        if not device or device.get('device_type') != 'cisco_xe':
            return

        try:
            interface_states = telemetry_data.get_interface_states()
            device_states = interface_states.get(device_name, {})
            interfaces_to_check = get_active_interfaces(device_name)

            status = 'healthy'
            for intf in interfaces_to_check:
                if intf in device_states:
                    if device_states[intf].get('state') == 'down':
                        status = 'degraded'
                        break

            socketio_instance.emit('device_status', {
                'device': device_name,
                'status': status,
                'interface': message.get('interface'),
                'interface_state': message.get('data', {}).get('new_state'),
                'timestamp': message.get('timestamp')
            })
            logger.info(f"[WS] Device status: {device_name} -> {status}")
        except Exception as e:
            logger.error(f"Error broadcasting device status: {e}")

    telemetry_data.subscribe(broadcast_telemetry_update)
    telemetry_data.subscribe(broadcast_device_status_change)
