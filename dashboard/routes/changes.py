"""
Change Management API Routes.

ITIL-compliant change workflow endpoints for creating, approving,
executing, and rolling back configuration changes.
"""

import asyncio
import logging

from flask import Blueprint, jsonify, request, g
from core.errors import safe_error_response, NotFoundError, ValidationError
from dashboard.auth import jwt_required, admin_required
from security.command_policy import validate_command

logger = logging.getLogger(__name__)

changes_bp = Blueprint('changes', __name__, url_prefix='/api/changes')


def get_current_user():
    """Get the current user from Flask g context."""
    return g.current_user if hasattr(g, 'current_user') else 'api'


from dashboard.utils.async_helpers import run_async


# =============================================================================
# Change Management Endpoints
# =============================================================================

@changes_bp.route('', methods=['GET'])
@jwt_required
def list_changes():
    """List change requests with optional filtering."""
    try:
        from core.change_workflows import get_change_manager, ChangeStatus
        from dashboard.api_server import log_event

        device = request.args.get('device')
        status = request.args.get('status')
        limit = int(request.args.get('limit', 50))

        manager = get_change_manager()
        status_filter = ChangeStatus(status) if status else None
        changes = manager.list_changes(device=device, status=status_filter, limit=limit)

        return jsonify({
            "changes": [c.to_dict() for c in changes],
            "count": len(changes),
            "status": "success"
        })
    except Exception as e:
        return safe_error_response(e, "list changes")


@changes_bp.route('/<change_id>', methods=['GET'])
@jwt_required
def get_change(change_id):
    """Get a specific change request by ID."""
    try:
        from core.change_workflows import get_change_manager

        manager = get_change_manager()
        change = manager.get_change(change_id)

        if not change:
            raise NotFoundError(f"Change '{change_id}' not found")

        return jsonify({
            "change": change.to_dict(),
            "status": "success"
        })
    except NotFoundError:
        raise
    except Exception as e:
        return safe_error_response(e, f"get change {change_id}")


@changes_bp.route('', methods=['POST'])
@jwt_required
def create_change():
    """Create a new change request."""
    try:
        from core.change_workflows import get_change_manager, ChangeType
        from dashboard.api_server import log_event

        data = request.get_json()
        if not data:
            raise ValidationError("No data provided")

        # Required fields
        device = data.get('device')
        description = data.get('description')
        commands = data.get('commands', [])

        if not device or not description:
            raise ValidationError("device and description are required")

        if not commands and not data.get('command_string'):
            raise ValidationError("commands or command_string is required")

        # Parse command_string if provided
        if data.get('command_string'):
            commands = [line.strip() for line in data['command_string'].split('\n') if line.strip()]

        # Handle commands passed as string (with newlines) instead of list
        if isinstance(commands, str):
            commands = [line.strip() for line in commands.split('\n') if line.strip()]

        # Validate each command against security policy
        # Config commands may start with operator prefixes (e.g. 'ip address'),
        # so grant both permissions for the blocklist check.
        for cmd in commands:
            is_valid, error_msg = validate_command(cmd, ["run_config_commands", "run_show_commands"])
            if not is_valid:
                raise ValidationError(f"Command blocked: {cmd!r} — {error_msg}")

        # Optional fields
        change_type = data.get('change_type', 'config')
        validation_checks = data.get('validation_checks', [])

        # Handle validation_checks passed as string
        if isinstance(validation_checks, str):
            validation_checks = [line.strip() for line in validation_checks.split('\n') if line.strip()]
        require_approval = data.get('require_approval', True)
        auto_rollback = data.get('auto_rollback', True)

        # Validate change type
        try:
            ctype = ChangeType(change_type)
        except ValueError:
            raise ValidationError(f"Invalid change_type: {change_type}")

        manager = get_change_manager()
        user = get_current_user()

        change = run_async(manager.create_change(
            device=device,
            description=description,
            commands=commands,
            change_type=ctype,
            validation_checks=validation_checks,
            created_by=user,
            require_approval=require_approval,
            auto_rollback=auto_rollback,
        ))

        log_event("change_create", device=device, details=f"Change {change.id}: {description}", user=user)

        return jsonify({
            "change": change.to_dict(),
            "message": f"Change request {change.id} created",
            "status": "success"
        }), 201

    except ValidationError:
        raise
    except Exception as e:
        return safe_error_response(e, "create change request")


@changes_bp.route('/<change_id>/approve', methods=['POST'])
@admin_required
def approve_change(change_id):
    """Approve a change request (admin only)."""
    try:
        from core.change_workflows import get_change_manager
        from dashboard.api_server import log_event

        manager = get_change_manager()
        approved_by = get_current_user()

        change = run_async(manager.approve_change(change_id, approved_by))

        log_event("change_approve", device=change.device,
                  details=f"Change {change_id} approved by {approved_by}", user=approved_by)

        return jsonify({
            "change": change.to_dict(),
            "message": f"Change {change_id} approved",
            "status": "success"
        })

    except ValueError as e:
        raise ValidationError(str(e))
    except Exception as e:
        return safe_error_response(e, f"approve change {change_id}")


@changes_bp.route('/<change_id>/reject', methods=['POST'])
@admin_required
def reject_change(change_id):
    """Reject a change request (admin only)."""
    try:
        from core.change_workflows import get_change_manager, ChangeStatus
        from dashboard.api_server import log_event

        manager = get_change_manager()
        change = manager.get_change(change_id)

        if not change:
            raise NotFoundError(f"Change '{change_id}' not found")

        if change.status not in (ChangeStatus.DRAFT, ChangeStatus.PENDING_APPROVAL):
            raise ValidationError(f"Change '{change_id}' cannot be rejected (status: {change.status.value})")

        # Update status to cancelled
        user = get_current_user()
        change.status = ChangeStatus.CANCELLED
        change.error = f"Rejected by {user}"
        manager._save_change(change)

        log_event("change_reject", device=change.device, details=f"Change {change_id} rejected", user=user)

        return jsonify({
            "change": change.to_dict(),
            "message": f"Change {change_id} rejected",
            "status": "success"
        })

    except (NotFoundError, ValidationError):
        raise
    except Exception as e:
        return safe_error_response(e, f"reject change {change_id}")


@changes_bp.route('/<change_id>/execute', methods=['POST'])
@admin_required
def execute_change(change_id):
    """Execute an approved change request (admin only)."""
    try:
        from core.change_workflows import get_change_manager
        from dashboard.api_server import log_event

        # Use silent=True to handle empty body without 400 error
        data = request.get_json(silent=True) or {}
        skip_validation = data.get('skip_validation', False)

        manager = get_change_manager()
        user = get_current_user()

        change = run_async(manager.execute_change(change_id, skip_validation=skip_validation))

        log_event("change_execute", device=change.device,
                  details=f"Change {change_id}: {change.status.value}",
                  status="success" if change.status.value == "completed" else "warning",
                  user=user)

        return jsonify({
            "change": change.to_dict(),
            "message": f"Change {change_id} executed (status: {change.status.value})",
            "status": "success"
        })

    except ValueError as e:
        raise ValidationError(str(e))
    except Exception as e:
        return safe_error_response(e, f"execute change {change_id}")


@changes_bp.route('/<change_id>/rollback', methods=['POST'])
@admin_required
def rollback_change(change_id):
    """Rollback a completed or failed change (admin only)."""
    try:
        from core.change_workflows import get_change_manager
        from dashboard.api_server import log_event

        manager = get_change_manager()
        user = get_current_user()

        change = run_async(manager.rollback_change(change_id))

        log_event("change_rollback", device=change.device, details=f"Change {change_id} rolled back", user=user)

        return jsonify({
            "change": change.to_dict(),
            "message": f"Change {change_id} rolled back",
            "status": "success"
        })

    except ValueError as e:
        raise ValidationError(str(e))
    except Exception as e:
        return safe_error_response(e, f"rollback change {change_id}")


@changes_bp.route('/<change_id>/cancel', methods=['POST'])
@admin_required
def cancel_change(change_id):
    """Cancel a change request (admin only)."""
    try:
        from core.change_workflows import get_change_manager
        from dashboard.api_server import log_event

        data = request.get_json(silent=True) or {}
        reason = data.get('reason', '')

        manager = get_change_manager()
        user = get_current_user()

        change = run_async(
            manager.cancel_change(
                change_id,
                cancelled_by=user,
                reason=reason
            )
        )

        log_event("change_cancel", device=change.device, details=f"Change {change_id} cancelled", status="info", user=user)

        return jsonify({
            "change": change.to_dict(),
            "message": f"Change {change_id} cancelled",
            "status": "success"
        })

    except ValueError as e:
        raise ValidationError(str(e))
    except Exception as e:
        return safe_error_response(e, f"cancel change {change_id}")


@changes_bp.route('/types', methods=['GET'])
@jwt_required
def get_change_types():
    """Get available change types."""
    from core.change_workflows import ChangeType, ChangeStatus

    return jsonify({
        "change_types": [
            {"value": t.value, "label": t.value.replace("_", " ").title()}
            for t in ChangeType
        ],
        "status_types": [
            {"value": s.value, "label": s.value.replace("_", " ").title()}
            for s in ChangeStatus
        ],
        "status": "success"
    })
