"""
RAG (Retrieval-Augmented Generation) module for documentation chatbot.

Provides:
- Document ingestion (PDF, HTML)
- Semantic search via ChromaDB
- Claude-powered response generation
"""

from .models import (
    DocumentChunk,
    SearchResult,
    ChatMessage,
    ChatRequest,
    ChatResponse,
    IngestRequest,
    IngestResponse,
    RAGStats,
)
from .ingest import DocumentIngestor
from .query import RAGQueryEngine

__all__ = [
    # Models
    "DocumentChunk",
    "SearchResult",
    "ChatMessage",
    "ChatRequest",
    "ChatResponse",
    "IngestRequest",
    "IngestResponse",
    "RAGStats",
    # Core classes
    "DocumentIngestor",
    "RAGQueryEngine",
]
