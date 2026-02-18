"""
Chat and RAG API Routes.

AI-powered documentation chatbot and usage tracking endpoints.
"""

import logging
from pathlib import Path

from flask import Blueprint, jsonify, request, g
from core.errors import safe_error_response, ValidationError
from dashboard.auth import jwt_required, admin_required

logger = logging.getLogger(__name__)

chat_bp = Blueprint('chat', __name__)


@chat_bp.route('/api/chat', methods=['POST'])
@jwt_required
def rag_chat():
    """Chat with the RAG-powered documentation assistant."""
    # Import from shared module to avoid circular imports
    from dashboard.shared import (
        get_rag_query_engine, decode_token, log_event,
        validate_query, validate_model, validate_conversation_history, SanitizationError
    )
    from dashboard.quota import (
        check_quota, record_usage, get_organization_for_user,
        UsageRecord, QUOTA_ENFORCEMENT_ENABLED
    )

    data = request.get_json()

    if not data:
        raise ValidationError("No data provided")

    message = data.get('message')
    if not message:
        raise ValidationError("Missing message")

    # Get username early for logging (before auth check)
    username = 'anonymous'
    auth_header = request.headers.get('Authorization')
    if auth_header and auth_header.startswith('Bearer '):
        try:
            payload = decode_token(auth_header.split(' ')[1])
            if payload:
                username = payload.get('sub', 'anonymous')
        except Exception:
            pass

    # Input sanitization to prevent prompt injection
    try:
        message = validate_query(message)
    except SanitizationError as e:
        log_event("security", details=f"Query blocked: {str(e)}", status="warning", user=username)
        return jsonify({"error": "Invalid query", "status": "error"}), 400

    # Model selection with validation
    model = validate_model(data.get('model', 'claude-sonnet-4-20250514'))

    # Conversation history validation
    conversation_history = validate_conversation_history(data.get('history', []))

    # Get full auth details (permissions, user_id, org_id) for quota and tool access
    permissions = []
    user_id = None
    org_id = None
    if auth_header and auth_header.startswith('Bearer '):
        try:
            payload = decode_token(auth_header.split(' ')[1])
            if payload:
                user_id = payload.get('user_id')
                permissions = payload.get('permissions', [])
                # Get organization for quota checking
                if user_id:
                    org_id = get_organization_for_user(user_id)
        except Exception:
            pass  # Invalid token = no permissions (anonymous access)

    # Check quota before processing (if quota enforcement is enabled)
    if QUOTA_ENFORCEMENT_ENABLED and org_id:
        quota_status = check_quota(org_id)
        if not quota_status.allowed:
            return jsonify({
                "error": "Quota exceeded",
                "message": quota_status.message,
                "usage": {
                    "used": quota_status.used,
                    "limit": quota_status.limit,
                    "remaining": quota_status.remaining,
                    "billing_period": quota_status.billing_period,
                    "reset_date": quota_status.reset_date
                },
                "status": "error"
            }), 402  # Payment Required

    try:
        engine = get_rag_query_engine()
        response = engine.chat(
            message, model=model, permissions=permissions,
            conversation_history=conversation_history
        )

        # Record usage after successful response (if user is authenticated with org)
        usage_data = None
        if response.usage and org_id and user_id:
            usage_record = UsageRecord(
                input_tokens=response.usage.input_tokens,
                output_tokens=response.usage.output_tokens,
                model=response.usage.model or model
            )
            record_usage(org_id, user_id, usage_record)
            usage_data = {
                "input_tokens": response.usage.input_tokens,
                "output_tokens": response.usage.output_tokens,
                "total_tokens": response.usage.total_tokens,
                "model": response.usage.model or model
            }

        log_event("rag_chat", details=f"Query by {username}: {message[:50]}...", user=username)

        result = {
            "response": response.response,
            "sources": response.sources,
            "status": "success"
        }
        if usage_data:
            result["usage"] = usage_data

        return jsonify(result)
    except ValueError as e:
        # API key not set - safe to expose as it's a configuration issue
        logger.error(f"RAG chat ValueError: {e}")
        return jsonify({
            "error": "Chat service configuration error",
            "status": "error"
        }), 500
    except Exception as e:
        log_event("rag_chat", details="Chat query failed", status="error")
        return safe_error_response(e, "process chat query")


@chat_bp.route('/api/ingest', methods=['POST'])
@admin_required
def rag_ingest():
    """Ingest documents into the RAG system (admin only)."""
    from dashboard.shared import get_rag_ingestor, log_event

    data = request.get_json()

    if not data:
        raise ValidationError("No data provided")

    path = data.get('path')
    doc_type = data.get('doc_type', 'project')

    if not path:
        raise ValidationError("Missing path")

    if doc_type not in ['vendor', 'project']:
        raise ValidationError("doc_type must be 'vendor' or 'project'")

    # Restrict paths to the project directory to prevent arbitrary filesystem reads
    project_root = Path(__file__).parent.parent.parent.resolve()
    try:
        resolved = Path(path).resolve()
        if not str(resolved).startswith(str(project_root)):
            raise ValidationError(
                "Path must be within the project directory. "
                "Traversal outside the project root is not allowed."
            )
    except (OSError, ValueError):
        raise ValidationError("Invalid file path")

    try:
        ingestor = get_rag_ingestor()
        file_path = Path(path)

        if file_path.is_dir():
            result = ingestor.ingest_directory(path, doc_type)
        else:
            result = ingestor.ingest_file(path, doc_type)

        log_event("rag_ingest", details=f"Ingested: {path}", status=result.status, user=g.current_user)

        return jsonify({
            "status": result.status,
            "documents_ingested": result.documents_ingested,
            "chunks_created": result.chunks_created,
            "message": result.message
        })
    except Exception as e:
        log_event("rag_ingest", details="Ingest failed", status="error", user=g.current_user)
        return safe_error_response(e, "ingest documents")


@chat_bp.route('/api/rag/stats')
@jwt_required
def rag_stats():
    """Get RAG system statistics."""
    from dashboard.shared import get_rag_query_engine

    try:
        engine = get_rag_query_engine()
        stats = engine.get_stats()

        return jsonify({
            "document_count": stats.document_count,
            "chunk_count": stats.chunk_count,
            "collection_name": stats.collection_name,
            "status": "success"
        })
    except Exception as e:
        return safe_error_response(e, "get RAG stats")


@chat_bp.route('/api/usage', methods=['GET'])
@jwt_required
def get_user_usage():
    """Get current user's organization usage and quota status."""
    from dashboard.shared import decode_token, get_token_from_request
    from dashboard.quota import (
        get_organization_for_user, get_usage_summary, check_quota,
        get_user_usage as get_user_usage_details
    )

    user_id = g.current_user_id if hasattr(g, 'current_user_id') else None

    # Try to get user_id from JWT payload if not in g
    if not user_id:
        token = get_token_from_request()
        if token:
            payload = decode_token(token)
            if payload:
                user_id = payload.get('user_id')

    if not user_id:
        return jsonify({
            "error": "User not authenticated",
            "status": "error"
        }), 401

    org_id = get_organization_for_user(user_id)

    if not org_id:
        return jsonify({
            "organization": None,
            "quota": None,
            "usage": None,
            "message": "User not assigned to an organization",
            "status": "success"
        })

    # Get quota status and usage summary
    quota_status = check_quota(org_id)
    org_usage = get_usage_summary(org_id)
    user_usage = get_user_usage_details(user_id)

    return jsonify({
        "organization_id": org_id,
        "quota": {
            "allowed": quota_status.allowed,
            "limit": quota_status.limit,
            "used": quota_status.used,
            "remaining": quota_status.remaining,
            "usage_percent": org_usage.get("usage_percent", 0),
            "billing_period": quota_status.billing_period,
            "reset_date": quota_status.reset_date
        },
        "organization_usage": {
            "total_tokens": org_usage.get("total_tokens", 0),
            "request_count": org_usage.get("request_count", 0)
        },
        "user_usage": {
            "input_tokens": user_usage.get("input_tokens", 0),
            "output_tokens": user_usage.get("output_tokens", 0),
            "total_tokens": user_usage.get("total_tokens", 0),
            "request_count": user_usage.get("request_count", 0)
        },
        "status": "success"
    })
