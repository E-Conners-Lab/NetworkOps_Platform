"""
Cache Management API Routes.

Extracted from api_server.py lines 1185-1223.
"""

import logging

from flask import Blueprint, g, jsonify

from dashboard.auth import jwt_required, permission_required

logger = logging.getLogger(__name__)

cache_bp = Blueprint('cache', __name__)


@cache_bp.route('/api/cache/stats')
@jwt_required
@permission_required('manage_users')
def get_cache_stats():
    """Get API response cache statistics."""
    from dashboard.extensions import cache

    try:
        cache_type = cache.config.get('CACHE_TYPE', 'simple')
        if cache_type == 'redis':
            import redis
            from config.settings import get_settings
            settings = get_settings()
            redis_client = redis.from_url(settings.redis.redis_url)
            info = redis_client.info()
            api_keys = list(redis_client.scan_iter(match='flask_cache_*'))
            return jsonify({
                'status': 'ok',
                'cache_type': 'redis',
                'redis_version': info.get('redis_version'),
                'used_memory_human': info.get('used_memory_human'),
                'connected_clients': info.get('connected_clients'),
                'api_cache_keys': len(api_keys),
            })
        else:
            return jsonify({
                'status': 'ok',
                'cache_type': 'simple',
                'message': 'Simple in-memory cache (no detailed stats)'
            })
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


@cache_bp.route('/api/cache', methods=['DELETE'])
@jwt_required
@permission_required('manage_users')
def clear_cache():
    """Clear all API response caches."""
    from dashboard.extensions import cache
    from core import log_event

    try:
        cache.clear()
        log_event('cache_clear', details='API response cache cleared', user=g.current_user)
        return jsonify({'status': 'ok', 'message': 'Cache cleared successfully'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500
