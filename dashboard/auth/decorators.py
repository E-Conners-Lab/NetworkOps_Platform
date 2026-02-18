"""
Flask route decorators for authentication and authorization.

Provides:
- jwt_required: Require valid JWT token
- permission_required: Require specific permissions
- admin_required: Require admin permissions
- role_required: Require specific roles (legacy)
"""
from functools import wraps

from flask import g, jsonify

from .tokens import get_token_from_request, decode_token


def jwt_required(f):
    """Decorator to require valid JWT token for endpoint.

    Sets g.current_user, g.current_role, g.current_permissions on success.
    Blocks restricted (password-change-only) tokens from accessing anything
    except password change, logout, and verify endpoints.
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        from flask import request

        token = get_token_from_request()

        if not token:
            return jsonify({"error": "Missing authorization token"}), 401

        payload = decode_token(token)
        if not payload:
            return jsonify({"error": "Invalid or expired token"}), 401

        # Store user info in Flask's g object for access in route
        g.current_user = payload.get("sub")
        g.current_role = payload.get("role")
        g.current_permissions = payload.get("permissions", [])

        # Enforce restricted password-change-only tokens
        if g.current_permissions == ["change_own_password"]:
            allowed_paths = {
                "/api/auth/change-password",
                "/api/auth/logout",
                "/api/auth/verify",
            }
            if request.path not in allowed_paths:
                return jsonify({"error": "Password change required before accessing this resource"}), 403

        return f(*args, **kwargs)
    return decorated


def permission_required(*required_permissions):
    """Decorator factory to require specific permissions.

    Usage:
        @permission_required("run_config_commands")
        def configure_device():
            ...

        @permission_required("manage_users", "manage_groups")
        def admin_action():
            ...
    """
    def decorator(f):
        @wraps(f)
        @jwt_required
        def decorated(*args, **kwargs):
            user_perms = set(g.current_permissions)
            required = set(required_permissions)

            if not required.intersection(user_perms):
                return jsonify({
                    "error": f"Permission denied. Required: {', '.join(required_permissions)}"
                }), 403
            return f(*args, **kwargs)
        return decorated
    return decorator


def admin_required(f):
    """Decorator to require manage_users or manage_groups permission."""
    @wraps(f)
    @jwt_required
    def decorated(*args, **kwargs):
        # Check for admin permissions (manage_users or manage_groups)
        admin_perms = {"manage_users", "manage_groups"}
        user_perms = set(g.current_permissions)

        if not admin_perms.intersection(user_perms):
            return jsonify({"error": "Admin access required"}), 403
        return f(*args, **kwargs)
    return decorated


def role_required(*allowed_roles):
    """Decorator factory to require specific roles (backward compatibility).

    Usage:
        @role_required("admin")
        def admin_only():
            ...

        @role_required("admin", "operator")
        def staff_only():
            ...
    """
    def decorator(f):
        @wraps(f)
        @jwt_required
        def decorated(*args, **kwargs):
            if g.current_role not in allowed_roles:
                return jsonify({
                    "error": f"Access denied. Required roles: {', '.join(allowed_roles)}"
                }), 403
            return f(*args, **kwargs)
        return decorated
    return decorator


def has_permission(permission: str) -> bool:
    """Helper to check if current user has a permission (use inside routes).

    Usage:
        @jwt_required
        def some_route():
            if has_permission("run_config_commands"):
                # allow config changes
            ...
    """
    return permission in getattr(g, 'current_permissions', [])
