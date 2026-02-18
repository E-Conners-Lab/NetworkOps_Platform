"""
Shared utilities for dashboard routes.

This module provides utilities that need to be shared between api_server.py
and route blueprint files without causing circular imports.
"""

# Re-export auth utilities (from auth.py)
from dashboard.auth import decode_token, get_token_from_request

# Re-export logging utilities (from core)
from core import log_event

# Re-export sanitization utilities (from rag.sanitizer)
from rag.sanitizer import (
    validate_query,
    validate_model,
    validate_conversation_history,
    SanitizationError
)

# RAG engine singletons (lazy-loaded)
_rag_ingestor = None
_rag_query_engine = None


def get_rag_ingestor():
    """Get the RAG document ingestor singleton."""
    global _rag_ingestor
    if _rag_ingestor is None:
        from rag import DocumentIngestor
        _rag_ingestor = DocumentIngestor()
    return _rag_ingestor


def get_rag_query_engine():
    """Get the RAG query engine singleton."""
    global _rag_query_engine
    if _rag_query_engine is None:
        from rag import RAGQueryEngine
        _rag_query_engine = RAGQueryEngine()
    return _rag_query_engine
