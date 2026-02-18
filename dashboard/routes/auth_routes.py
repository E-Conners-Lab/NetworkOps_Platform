"""
Authentication and authorization endpoints for the NetworkOps API.

Provides login, logout, token refresh, user management, group management, and MFA.
Extracted from api_server.py to improve separation of concerns.
"""

import os
from flask import Blueprint, jsonify, request, g

from dashboard.auth import (
    authenticate_user,
    jwt_required,
    admin_required,
    permission_required,
    has_permission,
    get_users_list,
    decode_token,
    get_token_from_request,
    create_user,
    update_user,
    delete_user,
    reactivate_user,
    change_password,
    get_all_permissions,
    get_all_groups,
    get_group,
    create_group,
    update_group,
    delete_group,
    assign_user_to_groups,
    check_password_change_required,
    clear_password_change_required,
)
from core import log_event

# Create blueprint
auth_bp = Blueprint('auth', __name__, url_prefix='/api/auth')


# =============================================================================
# Login / Logout / Token Management
# =============================================================================

@auth_bp.route('/login', methods=['POST'])
def login():
    """
    Authenticate user and return JWT token.
    Rate limited to 10 per minute (applied at registration).
    """
    data = request.get_json()

    if not data or not isinstance(data, dict):
        return jsonify({"error": "No credentials provided"}), 400

    username = data.get("username")
    password = data.get("password")

    # Type validation - prevent type confusion attacks
    if not isinstance(username, str) or not isinstance(password, str):
        return jsonify({"error": "Username and password must be strings"}), 400

    if not username or not password:
        return jsonify({"error": "Username and password required"}), 400

    # Length limits
    if len(username) > 100 or len(password) > 200:
        return jsonify({"error": "Credentials exceed maximum length"}), 400

    success, auth_data, error = authenticate_user(username, password)

    if success:
        log_event("auth", "system", f"Login successful: {username}", "success")
        password_change_required = check_password_change_required(username)

        if password_change_required:
            # Issue a restricted token that only allows password change
            from dashboard.auth import create_token, get_user, get_user_id_by_username
            user = get_user(username)
            user_id = get_user_id_by_username(username) if user else None
            restricted_token = create_token(
                username, user["role"] if user else "operator",
                user_id, ["change_own_password"]
            )

            # Register restricted token in session so single-session validation accepts it
            from dashboard.sessions import get_session_manager, SINGLE_SESSION_ENABLED
            if SINGLE_SESSION_ENABLED and user_id:
                import jwt as pyjwt
                access_jti = pyjwt.decode(restricted_token, options={"verify_signature": False})["jti"]
                # No refresh token for restricted sessions — use empty string
                get_session_manager().create_session(user_id, access_jti, "")

            return jsonify({
                "token": restricted_token,
                "refresh_token": None,
                "username": username,
                "permissions": ["change_own_password"],
                "groups": auth_data["groups"],
                "message": "Password change required",
                "password_change_required": True,
            })

        return jsonify({
            "token": auth_data["token"],
            "refresh_token": auth_data.get("refresh_token"),
            "username": username,
            "permissions": auth_data["permissions"],
            "groups": auth_data["groups"],
            "message": "Login successful",
            "password_change_required": False,
        })
    else:
        log_event("auth", "system", f"Login failed: {username}", "error")
        return jsonify({"error": error}), 401


@auth_bp.route('/me', methods=['GET'])
@jwt_required
def get_current_user():
    """Get current authenticated user info."""
    return jsonify({
        "username": g.current_user,
        "role": g.current_role
    })


@auth_bp.route('/verify', methods=['GET'])
def verify_token():
    """Verify if a token is valid (for frontend validation)."""
    token = get_token_from_request()
    if not token:
        return jsonify({"valid": False, "error": "No token provided"}), 401

    payload = decode_token(token)
    if payload:
        return jsonify({
            "valid": True,
            "username": payload.get("sub"),
            "role": payload.get("role")
        })
    else:
        return jsonify({"valid": False, "error": "Invalid or expired token"}), 401


@auth_bp.route('/refresh', methods=['POST'])
def refresh_access_token():
    """Get a new access token using a refresh token (with rotation)."""
    from dashboard.auth import (
        decode_refresh_token, create_token, create_refresh_token,
        invalidate_token, get_user, get_user_permissions, get_user_groups,
        DEFAULT_PERMISSIONS,
    )

    data = request.get_json()
    if not data:
        return jsonify({"error": "No data provided"}), 400

    refresh_token = data.get("refresh_token")
    if not refresh_token:
        return jsonify({"error": "Refresh token required"}), 400

    # Validate refresh token
    payload = decode_refresh_token(refresh_token)
    if not payload:
        return jsonify({"error": "Invalid or expired refresh token"}), 401

    username = payload.get("sub")
    user_id = payload.get("user_id")

    # Get current user data
    user = get_user(username)
    if not user:
        return jsonify({"error": "User not found"}), 401

    # Get permissions and create new access token
    permissions = get_user_permissions(user_id) if user_id else []
    if not permissions:
        permissions = ["view_topology", "run_show_commands"]
        if user["role"] == "admin":
            permissions = [p[0] for p in DEFAULT_PERMISSIONS]

    new_token = create_token(username, user["role"], user_id, permissions)

    # Rotate refresh token: blacklist the old one, issue a new one
    invalidate_token(refresh_token, is_refresh=True)
    new_refresh_token = create_refresh_token(username, user_id)

    # Update session with new JTIs so single-session validation accepts them
    from dashboard.sessions import get_session_manager, SINGLE_SESSION_ENABLED
    if SINGLE_SESSION_ENABLED and user_id:
        import jwt as pyjwt
        new_access_jti = pyjwt.decode(new_token, options={"verify_signature": False})["jti"]
        new_refresh_jti = pyjwt.decode(new_refresh_token, options={"verify_signature": False})["jti"]
        get_session_manager().update_session_tokens(user_id, new_access_jti, new_refresh_jti)

    log_event("auth", "system", f"Token refreshed for: {username}", "success")

    return jsonify({
        "token": new_token,
        "refresh_token": new_refresh_token,
        "username": username,
        "permissions": permissions,
    })


@auth_bp.route('/logout', methods=['POST'])
@jwt_required
def logout():
    """Logout by invalidating the current token."""
    from dashboard.auth import invalidate_token

    # Get tokens from request
    access_token = get_token_from_request()
    data = request.get_json() or {}
    refresh_token = data.get("refresh_token")

    # Invalidate access token
    if access_token:
        invalidate_token(access_token, is_refresh=False)

    # Invalidate refresh token if provided
    if refresh_token:
        invalidate_token(refresh_token, is_refresh=True)

    log_event("auth", details="Logged out", user=g.current_user)

    return jsonify({"message": "Logged out successfully"})


@auth_bp.route('/sessions', methods=['GET'])
@jwt_required
def get_current_session():
    """Get current session information."""
    from dashboard.sessions import get_session_manager, SINGLE_SESSION_ENABLED
    from dashboard.auth import get_user_id_by_username

    if not SINGLE_SESSION_ENABLED:
        return jsonify({
            "enabled": False,
            "message": "Single session mode is disabled"
        })

    user_id = get_user_id_by_username(g.current_user)
    if not user_id:
        return jsonify({"error": "User not found"}), 404

    session = get_session_manager().get_user_session(user_id)

    return jsonify({
        "enabled": True,
        "session": session
    })


# =============================================================================
# User Management
# =============================================================================

@auth_bp.route('/users', methods=['GET'])
@permission_required('manage_users')
def list_users():
    """List all users (requires manage_users permission)."""
    return jsonify(get_users_list())


@auth_bp.route('/users', methods=['POST'])
@permission_required('manage_users')
def create_new_user():
    """Create a new user (requires manage_users permission)."""
    data = request.get_json()
    if not data:
        return jsonify({"error": "No data provided"}), 400

    username = data.get("username")
    password = data.get("password")
    role = data.get("role", "operator")

    success, message = create_user(username, password, role)

    if success:
        log_event("auth", details=f"Created user: {username} ({role})", user=g.current_user)
        return jsonify({"message": message, "username": username, "role": role}), 201
    else:
        return jsonify({"error": message}), 400


@auth_bp.route('/users/<username>', methods=['PUT'])
@permission_required('manage_users')
def update_existing_user(username):
    """Update a user (requires manage_users permission)."""
    data = request.get_json()
    if not data:
        return jsonify({"error": "No data provided"}), 400

    password = data.get("password")
    role = data.get("role")
    is_active = data.get("is_active")

    success, message = update_user(username, password=password, role=role, is_active=is_active)

    if success:
        log_event("auth", details=f"Updated user: {username}", user=g.current_user)
        return jsonify({"message": message})
    else:
        return jsonify({"error": message}), 400


@auth_bp.route('/users/<username>', methods=['DELETE'])
@permission_required('manage_users')
def delete_existing_user(username):
    """Delete/deactivate a user (requires manage_users permission)."""
    hard_delete = request.args.get("hard", "false").lower() == "true"

    # Prevent admin from deleting themselves
    if username == g.current_user:
        return jsonify({"error": "Cannot delete your own account"}), 400

    success, message = delete_user(username, hard_delete=hard_delete)

    if success:
        action = "Deleted" if hard_delete else "Deactivated"
        log_event("auth", details=f"{action} user: {username}", user=g.current_user)
        return jsonify({"message": message})
    else:
        return jsonify({"error": message}), 400


@auth_bp.route('/users/<username>/reactivate', methods=['POST'])
@permission_required('manage_users')
def reactivate_existing_user(username):
    """Reactivate a deactivated user (requires manage_users permission)."""
    success, message = reactivate_user(username)

    if success:
        log_event("auth", details=f"Reactivated user: {username}", user=g.current_user)
        return jsonify({"message": message})
    else:
        return jsonify({"error": message}), 400


@auth_bp.route('/change-password', methods=['POST'])
@jwt_required
def change_user_password():
    """Change current user's password."""
    data = request.get_json()
    if not data:
        return jsonify({"error": "No data provided"}), 400

    old_password = data.get("old_password")
    new_password = data.get("new_password")

    if not old_password or not new_password:
        return jsonify({"error": "Old and new passwords required"}), 400

    success, message = change_password(g.current_user, old_password, new_password)

    if success:
        clear_password_change_required(g.current_user)
        log_event("auth", details="Password changed", user=g.current_user)
        return jsonify({"message": message})
    else:
        return jsonify({"error": message}), 400


@auth_bp.route('/users/<username>/groups', methods=['PUT'])
@permission_required('manage_users')
def assign_groups_to_user(username):
    """Assign groups to a user (requires manage_users permission)."""
    data = request.get_json()
    if not data:
        return jsonify({"error": "No data provided"}), 400

    group_ids = data.get("group_ids", [])

    if not isinstance(group_ids, list):
        return jsonify({"error": "group_ids must be a list"}), 400

    success, message = assign_user_to_groups(username, group_ids)

    if success:
        log_event("auth", details=f"Updated groups for user: {username}", user=g.current_user)
        return jsonify({"message": message})
    return jsonify({"error": message}), 400


# =============================================================================
# Group Management
# =============================================================================

@auth_bp.route('/permissions', methods=['GET'])
@jwt_required
def list_permissions():
    """List all available permissions."""
    return jsonify(get_all_permissions())


@auth_bp.route('/groups', methods=['GET'])
@jwt_required
def list_groups():
    """List all groups with their permissions."""
    return jsonify(get_all_groups())


@auth_bp.route('/groups/<int:group_id>', methods=['GET'])
@jwt_required
def get_single_group(group_id):
    """Get a single group by ID."""
    group = get_group(group_id)
    if group:
        return jsonify(group)
    return jsonify({"error": "Group not found"}), 404


@auth_bp.route('/groups', methods=['POST'])
@permission_required('manage_groups')
def create_new_group():
    """Create a new group (requires manage_groups permission)."""
    data = request.get_json()
    if not data:
        return jsonify({"error": "No data provided"}), 400

    name = data.get("name")
    description = data.get("description", "")
    permissions = data.get("permissions", [])

    success, message, group_id = create_group(name, description, permissions)

    if success:
        log_event("auth", details=f"Created group: {name}", user=g.current_user)
        return jsonify({"message": message, "id": group_id}), 201
    return jsonify({"error": message}), 400


@auth_bp.route('/groups/<int:group_id>', methods=['PUT'])
@permission_required('manage_groups')
def update_existing_group(group_id):
    """Update a group (requires manage_groups permission)."""
    data = request.get_json()
    if not data:
        return jsonify({"error": "No data provided"}), 400

    name = data.get("name")
    description = data.get("description")
    permissions = data.get("permissions")

    success, message = update_group(group_id, name, description, permissions)

    if success:
        log_event("auth", details=f"Updated group ID: {group_id}", user=g.current_user)
        return jsonify({"message": message})
    return jsonify({"error": message}), 400


@auth_bp.route('/groups/<int:group_id>', methods=['DELETE'])
@permission_required('manage_groups')
def delete_existing_group(group_id):
    """Delete a group (requires manage_groups permission)."""
    success, message = delete_group(group_id)

    if success:
        log_event("auth", details=f"Deleted group ID: {group_id}", user=g.current_user)
        return jsonify({"message": message})
    return jsonify({"error": message}), 400


# =============================================================================
# MFA (Multi-Factor Authentication)
# =============================================================================

@auth_bp.route('/mfa/status', methods=['GET'])
@jwt_required
def mfa_status():
    """Get MFA status for current user."""
    from dashboard.mfa import get_mfa_manager, MFA_ENABLED
    from dashboard.auth import get_user_id_by_username

    if not MFA_ENABLED:
        return jsonify({
            "enabled": False,
            "global_enabled": False,
            "message": "MFA is disabled globally"
        })

    user_id = get_user_id_by_username(g.current_user)
    if not user_id:
        return jsonify({"error": "User not found"}), 404

    status = get_mfa_manager().get_mfa_status(user_id)

    return jsonify({
        "global_enabled": True,
        "is_enabled": status.is_enabled,
        "is_setup": status.is_setup,
        "recovery_codes_remaining": status.recovery_codes_remaining
    })


@auth_bp.route('/mfa/setup', methods=['POST'])
@jwt_required
def mfa_setup():
    """Begin MFA setup - returns QR code for authenticator app."""
    from dashboard.mfa import get_mfa_manager, MFA_ENABLED
    from dashboard.auth import get_user_id_by_username

    if not MFA_ENABLED:
        return jsonify({"error": "MFA is disabled"}), 400

    user_id = get_user_id_by_username(g.current_user)
    if not user_id:
        return jsonify({"error": "User not found"}), 404

    secret, qr_code = get_mfa_manager().setup_mfa(user_id, g.current_user)

    log_event("mfa", details="MFA setup initiated", status="info", user=g.current_user)

    return jsonify({
        "secret": secret,
        "qr_code": qr_code,
        "message": "Scan QR code with authenticator app, then confirm with a code"
    })


@auth_bp.route('/mfa/confirm', methods=['POST'])
@jwt_required
def mfa_confirm():
    """Confirm MFA setup with TOTP code."""
    from dashboard.mfa import get_mfa_manager, MFA_ENABLED
    from dashboard.auth import get_user_id_by_username

    if not MFA_ENABLED:
        return jsonify({"error": "MFA is disabled"}), 400

    data = request.get_json() or {}
    code = data.get("code", "").strip()

    if not code or len(code) != 6:
        return jsonify({"error": "Invalid code format"}), 400

    user_id = get_user_id_by_username(g.current_user)
    if not user_id:
        return jsonify({"error": "User not found"}), 404

    success, recovery_codes = get_mfa_manager().confirm_mfa(user_id, code)

    if not success:
        log_event("mfa", details="MFA confirmation failed", status="warning", user=g.current_user)
        return jsonify({"error": "Invalid code"}), 400

    log_event("mfa", details="MFA enabled", user=g.current_user)

    return jsonify({
        "message": "MFA enabled successfully",
        "recovery_codes": recovery_codes,
        "warning": "Save these recovery codes securely. They will not be shown again."
    })


@auth_bp.route('/mfa/verify', methods=['POST'])
def mfa_verify():
    """
    Verify MFA code to complete login.
    Rate limited to 10 per minute (applied at registration).
    """
    from dashboard.mfa import get_mfa_manager, MFA_ENABLED
    from dashboard.auth import verify_mfa_token, complete_mfa_login

    if not MFA_ENABLED:
        return jsonify({"error": "MFA is disabled"}), 400

    data = request.get_json() or {}
    mfa_token = data.get("mfa_token", "")
    code = data.get("code", "").strip()

    if not mfa_token or not code:
        return jsonify({"error": "Missing mfa_token or code"}), 400

    # Verify MFA token and get user info
    mfa_data = verify_mfa_token(mfa_token)
    if not mfa_data:
        return jsonify({"error": "Invalid or expired MFA token"}), 401

    user_id = mfa_data.get("user_id")
    username = mfa_data.get("username")

    # Verify TOTP code
    if not get_mfa_manager().verify_totp(user_id, code):
        log_event("mfa", details="MFA verification failed", status="warning", user=username)
        return jsonify({"error": "Invalid code"}), 401

    # Complete login - generate actual tokens
    tokens = complete_mfa_login(user_id, username)
    if not tokens:
        return jsonify({"error": "Login failed"}), 500

    log_event("mfa", details="MFA verification successful", user=username)

    return jsonify(tokens)


@auth_bp.route('/mfa/recovery', methods=['POST'])
def mfa_recovery():
    """
    Use recovery code to complete login.
    Rate limited to 5 per minute (applied at registration).
    """
    from dashboard.mfa import get_mfa_manager, MFA_ENABLED
    from dashboard.auth import verify_mfa_token, complete_mfa_login

    if not MFA_ENABLED:
        return jsonify({"error": "MFA is disabled"}), 400

    data = request.get_json() or {}
    mfa_token = data.get("mfa_token", "")
    recovery_code = data.get("recovery_code", "").strip()

    if not mfa_token or not recovery_code:
        return jsonify({"error": "Missing mfa_token or recovery_code"}), 400

    # Verify MFA token
    mfa_data = verify_mfa_token(mfa_token)
    if not mfa_data:
        return jsonify({"error": "Invalid or expired MFA token"}), 401

    user_id = mfa_data.get("user_id")
    username = mfa_data.get("username")

    # Verify recovery code
    if not get_mfa_manager().verify_recovery_code(user_id, recovery_code):
        log_event("mfa", details="Recovery code verification failed", status="warning", user=username)
        return jsonify({"error": "Invalid recovery code"}), 401

    # Complete login
    tokens = complete_mfa_login(user_id, username)
    if not tokens:
        return jsonify({"error": "Login failed"}), 500

    log_event("mfa", details="Login via recovery code", user=username)

    return jsonify(tokens)


@auth_bp.route('/mfa/disable', methods=['POST'])
@jwt_required
def mfa_disable():
    """Disable MFA (requires current TOTP code)."""
    from dashboard.mfa import get_mfa_manager, MFA_ENABLED
    from dashboard.auth import get_user_id_by_username

    if not MFA_ENABLED:
        return jsonify({"error": "MFA is disabled globally"}), 400

    data = request.get_json() or {}
    code = data.get("code", "").strip()

    if not code or len(code) != 6:
        return jsonify({"error": "Invalid code format"}), 400

    user_id = get_user_id_by_username(g.current_user)
    if not user_id:
        return jsonify({"error": "User not found"}), 404

    if not get_mfa_manager().disable_mfa(user_id, code):
        log_event("mfa", details="MFA disable failed - invalid code", status="warning", user=g.current_user)
        return jsonify({"error": "Invalid code"}), 400

    log_event("mfa", details="MFA disabled", status="info", user=g.current_user)

    return jsonify({"message": "MFA disabled successfully"})
