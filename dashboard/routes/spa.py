"""
SPA (Single Page Application) routes.

Serves the React frontend for production deployment.
Extracted from api_server.py lines 1699-1711.
"""

from flask import Blueprint, jsonify, request

spa_bp = Blueprint('spa', __name__)


@spa_bp.route('/')
def serve_index():
    """Serve React app index.html."""
    from flask import current_app
    return current_app.send_static_file('index.html')


@spa_bp.app_errorhandler(404)
def not_found(e):
    """Serve React app for client-side routing (SPA)."""
    if not request.path.startswith('/api/'):
        from flask import current_app
        return current_app.send_static_file('index.html')
    return jsonify({"error": "Not found"}), 404
