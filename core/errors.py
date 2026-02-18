"""
Centralized error handling for NetworkOps API.

Error Hierarchy:
- APIError (4xx): Expected errors with messages safe to expose to clients
- InternalError (5xx): Unexpected errors - never expose internal details

Usage:
    from core.errors import safe_error_response, NotFoundError, ValidationError

    # For expected errors (4xx) - raise with safe message
    raise NotFoundError(f"Device {device_name} not found")

    # For unexpected errors (5xx) - use safe_error_response
    except Exception as e:
        return safe_error_response(e, "create change request")
"""

import logging
import uuid
from flask import jsonify
from typing import Tuple, Any

logger = logging.getLogger(__name__)


# =============================================================================
# Exception Classes (4xx - Expected Errors)
# =============================================================================

class APIError(Exception):
    """
    Base class for expected API errors (4xx status codes).
    Messages are safe to expose to clients.
    """
    status_code = 400

    def __init__(self, message: str, status_code: int = None):
        super().__init__(message)
        if status_code is not None:
            self.status_code = status_code


class NotFoundError(APIError):
    """Resource not found (404)."""
    status_code = 404


class ValidationError(APIError):
    """Request validation failed (400)."""
    status_code = 400


class PermissionDeniedError(APIError):
    """Permission denied (403)."""
    status_code = 403


class AuthenticationError(APIError):
    """Authentication failed (401)."""
    status_code = 401


class ConflictError(APIError):
    """Resource conflict (409)."""
    status_code = 409


class RateLimitError(APIError):
    """Rate limit exceeded (429)."""
    status_code = 429


class ServiceUnavailableError(APIError):
    """Service temporarily unavailable (503)."""
    status_code = 503


# =============================================================================
# Internal Error (5xx - Never Expose)
# =============================================================================

class InternalError(Exception):
    """
    Unexpected internal errors (5xx status codes).
    Message should NEVER be exposed to clients.
    """
    pass


# =============================================================================
# Safe Error Response Helper
# =============================================================================

def safe_error_response(
    e: Exception,
    operation: str,
    include_error_id: bool = True
) -> Tuple[Any, int]:
    """
    Create a safe error response for API endpoints.

    For APIError subclasses (expected errors):
        - Returns the error message (safe to expose)
        - Uses the exception's status_code
        - Logs at WARNING level

    For all other exceptions (unexpected errors):
        - Returns generic message (never exposes internal details)
        - Returns 500 status code
        - Logs full exception at ERROR level

    Args:
        e: The exception that was caught
        operation: Human-readable description of what failed (e.g., "create device")
        include_error_id: Whether to include error_id for support reference

    Returns:
        Tuple of (json_response, status_code)

    Example:
        try:
            device = get_device(device_id)
            if not device:
                raise NotFoundError(f"Device {device_id} not found")
            # ... do something that might fail unexpectedly
        except APIError:
            raise  # Re-raise to be handled by Flask error handler
        except Exception as e:
            return safe_error_response(e, "fetch device configuration")
    """
    error_id = str(uuid.uuid4())[:8] if include_error_id else None

    if isinstance(e, APIError):
        # Expected error - safe to expose message
        log_extra = {'error_id': error_id} if error_id else {}
        logger.warning(f"{operation}: {e}", extra=log_extra)

        response = {"error": str(e)}
        if error_id:
            response["error_id"] = error_id

        return jsonify(response), e.status_code
    else:
        # Unexpected error - log full details, return generic message
        log_extra = {'error_id': error_id} if error_id else {}
        logger.exception(f"{operation} failed", extra=log_extra)

        response = {"error": f"{operation} failed"}
        if error_id:
            response["error_id"] = error_id

        return jsonify(response), 500


def register_error_handlers(app):
    """
    Register Flask error handlers for APIError exceptions.

    Call this in your Flask app factory:
        from core.errors import register_error_handlers
        register_error_handlers(app)
    """

    @app.errorhandler(APIError)
    def handle_api_error(e):
        """Handle all APIError subclasses."""
        error_id = str(uuid.uuid4())[:8]
        logger.warning(f"API error: {e}", extra={'error_id': error_id})
        return jsonify({
            "error": str(e),
            "error_id": error_id
        }), e.status_code

    @app.errorhandler(500)
    def handle_internal_error(e):
        """Handle unexpected 500 errors."""
        error_id = str(uuid.uuid4())[:8]
        logger.exception("Internal server error", extra={'error_id': error_id})
        return jsonify({
            "error": "Internal server error",
            "error_id": error_id
        }), 500
