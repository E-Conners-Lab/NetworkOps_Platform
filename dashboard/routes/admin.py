"""
Admin API Routes.

Administrative endpoints for quotas, organizations, feature flags, and metrics.
All routes require admin role.
"""

import logging

from flask import Blueprint, jsonify, request, g
from dashboard.auth import admin_required

logger = logging.getLogger(__name__)

admin_bp = Blueprint('admin', __name__, url_prefix='/api/admin')


@admin_bp.before_request
@admin_required
def require_admin():
    """All admin routes require admin role."""
    pass


# =============================================================================
# Quota Management
# =============================================================================

@admin_bp.route('/quotas', methods=['GET'])
def list_all_quotas():
    """Get quota status for all organizations (admin only)."""
    from dashboard.quota import get_all_quotas

    quotas = get_all_quotas()
    return jsonify({
        "quotas": quotas,
        "count": len(quotas),
        "status": "success"
    })


@admin_bp.route('/quotas/<int:org_id>', methods=['GET'])
def get_org_quota(org_id):
    """Get detailed quota info for a specific organization."""
    from dashboard.quota import get_organization, get_usage_summary, get_usage_history

    org = get_organization(org_id)
    if not org:
        return jsonify({"error": "Organization not found", "status": "error"}), 404

    usage = get_usage_summary(org_id)
    history = get_usage_history(org_id, months=6)

    return jsonify({
        "organization": org,
        "usage": usage,
        "history": history,
        "status": "success"
    })


@admin_bp.route('/quotas/<int:org_id>', methods=['PUT'])
def update_org_quota(org_id):
    """Update quota limit for an organization."""
    from dashboard.quota import update_quota, get_organization
    from dashboard.api_server import log_event

    org = get_organization(org_id)
    if not org:
        return jsonify({"error": "Organization not found", "status": "error"}), 404

    data = request.get_json()
    if not data:
        return jsonify({"error": "No data provided", "status": "error"}), 400

    monthly_limit = data.get('monthly_token_limit')
    if monthly_limit is None:
        return jsonify({"error": "monthly_token_limit is required", "status": "error"}), 400

    if not isinstance(monthly_limit, int) or monthly_limit < 0:
        return jsonify({"error": "monthly_token_limit must be a non-negative integer", "status": "error"}), 400

    success, message = update_quota(org_id, monthly_limit)

    if success:
        log_event("quota_update", details=f"Org {org_id} quota set to {monthly_limit:,}", user=g.current_user)
        return jsonify({"message": message, "status": "success"})
    else:
        return jsonify({"error": message, "status": "error"}), 400


@admin_bp.route('/quotas/<int:org_id>/reset', methods=['POST'])
def reset_org_usage(org_id):
    """Reset usage for an organization (admin only)."""
    from dashboard.quota import get_organization, reset_usage
    from dashboard.api_server import log_event

    org = get_organization(org_id)
    if not org:
        return jsonify({"error": "Organization not found", "status": "error"}), 404

    data = request.get_json() or {}
    billing_period = data.get('billing_period')  # Optional specific period

    success, message = reset_usage(org_id, billing_period)

    if success:
        log_event("quota_reset", details=f"Reset usage for org {org_id}", user=g.current_user)
        return jsonify({"message": message, "status": "success"})
    else:
        return jsonify({"error": message, "status": "error"}), 400


# =============================================================================
# Organization Management
# =============================================================================

@admin_bp.route('/organizations', methods=['GET'])
def list_organizations():
    """List all organizations."""
    from dashboard.quota import list_organizations as list_orgs

    orgs = list_orgs()
    return jsonify({
        "organizations": orgs,
        "count": len(orgs),
        "status": "success"
    })


@admin_bp.route('/organizations', methods=['POST'])
def create_organization():
    """Create a new organization."""
    from dashboard.quota import create_organization as create_org
    from dashboard.api_server import log_event

    data = request.get_json()
    if not data:
        return jsonify({"error": "No data provided", "status": "error"}), 400

    name = data.get('name')
    slug = data.get('slug')
    monthly_limit = data.get('monthly_token_limit')

    if not name or not slug:
        return jsonify({"error": "name and slug are required", "status": "error"}), 400

    success, message, org_id = create_org(name, slug, monthly_limit)

    if success:
        log_event("org_create", details=f"Created org: {name}", user=g.current_user)
        return jsonify({
            "message": message,
            "organization_id": org_id,
            "status": "success"
        }), 201
    else:
        return jsonify({"error": message, "status": "error"}), 400


@admin_bp.route('/organizations/<int:org_id>/users', methods=['GET'])
def get_org_users(org_id):
    """Get all users in an organization."""
    from dashboard.quota import get_organization, get_organization_users

    org = get_organization(org_id)
    if not org:
        return jsonify({"error": "Organization not found", "status": "error"}), 404

    users = get_organization_users(org_id)
    return jsonify({
        "organization": org,
        "users": users,
        "count": len(users),
        "status": "success"
    })


@admin_bp.route('/organizations/<int:org_id>/users', methods=['POST'])
def add_user_to_org(org_id):
    """Assign a user to an organization."""
    from dashboard.quota import get_organization, assign_user_to_organization
    from dashboard.auth import get_user_id_by_username
    from dashboard.api_server import log_event

    org = get_organization(org_id)
    if not org:
        return jsonify({"error": "Organization not found", "status": "error"}), 404

    data = request.get_json()
    if not data:
        return jsonify({"error": "No data provided", "status": "error"}), 400

    username = data.get('username')
    user_id = data.get('user_id')
    role = data.get('role', 'member')

    # Get user_id from username if not provided
    if not user_id and username:
        user_id = get_user_id_by_username(username)

    if not user_id:
        return jsonify({"error": "user_id or username is required", "status": "error"}), 400

    success, message = assign_user_to_organization(user_id, org_id, role)

    if success:
        log_event("org_user_add", details=f"Added user {user_id} to org {org_id}", user=g.current_user)
        return jsonify({"message": message, "status": "success"})
    else:
        return jsonify({"error": message, "status": "error"}), 400


# =============================================================================
# Feature Flags
# =============================================================================

@admin_bp.route('/feature-flags', methods=['GET'])
def get_feature_flags():
    """Get all feature flags with their current values and sources."""
    try:
        from core.feature_flags import flags
        return jsonify({
            "flags": flags.all_flags(),
            "details": flags.get_flag_info(),
            "status": "success"
        })
    except ImportError:
        return jsonify({
            "error": "Feature flags module not available",
            "status": "error"
        }), 500


@admin_bp.route('/feature-flags/refresh', methods=['POST'])
def refresh_feature_flags():
    """Refresh feature flags from config file and environment."""
    from dashboard.api_server import log_event

    try:
        from core.feature_flags import flags
        flags.refresh()
        log_event("feature_flags_refresh", details="Feature flags refreshed", user=g.current_user)
        return jsonify({
            "message": "Feature flags refreshed",
            "flags": flags.all_flags(),
            "status": "success"
        })
    except ImportError:
        return jsonify({
            "error": "Feature flags module not available",
            "status": "error"
        }), 500


# =============================================================================
# Metrics Management
# =============================================================================

@admin_bp.route('/metrics/save', methods=['POST'])
def save_automation_metrics():
    """Persist automation metrics to disk."""
    from dashboard.api_server import log_event

    try:
        from core.metrics import save_all_metrics
        success = save_all_metrics()
        if success:
            log_event("metrics_save", details="Automation metrics saved to disk", user=g.current_user)
            return jsonify({"message": "Metrics saved successfully", "status": "success"})
        else:
            return jsonify({"error": "Failed to save metrics", "status": "error"}), 500
    except ImportError:
        return jsonify({"error": "Metrics module not available", "status": "error"}), 500


@admin_bp.route('/metrics/load', methods=['POST'])
def load_automation_metrics():
    """Load automation metrics from disk."""
    from dashboard.api_server import log_event

    try:
        from core.metrics import load_all_metrics
        success = load_all_metrics()
        if success:
            log_event("metrics_load", details="Automation metrics loaded from disk", user=g.current_user)
            return jsonify({"message": "Metrics loaded successfully", "status": "success"})
        else:
            return jsonify({"message": "No saved metrics found", "status": "success"})
    except ImportError:
        return jsonify({"error": "Metrics module not available", "status": "error"}), 500
