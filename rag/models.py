"""
Pydantic models for RAG document storage and retrieval.
"""

from datetime import datetime
from typing import Optional
from pydantic import BaseModel, Field


class DocumentChunk(BaseModel):
    """A chunk of text from a document with metadata."""

    id: str = Field(description="Unique chunk identifier")
    content: str = Field(description="Text content of the chunk")
    source_file: str = Field(description="Original file path")
    page_number: Optional[int] = Field(default=None, description="Page number for PDFs")
    chunk_index: int = Field(description="Position of chunk within document")
    doc_type: str = Field(description="vendor or project")
    timestamp: datetime = Field(default_factory=datetime.utcnow)

    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }


class SearchResult(BaseModel):
    """A search result with relevance score."""

    chunk: DocumentChunk
    score: float = Field(description="Similarity score (0-1)")


class ChatMessage(BaseModel):
    """A message in a chat conversation."""

    role: str = Field(description="user or assistant")
    content: str = Field(description="Message content")
    sources: Optional[list[str]] = Field(default=None, description="Source citations")
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class ChatRequest(BaseModel):
    """Request to the chat endpoint."""

    message: str = Field(description="User's question")
    session_id: Optional[str] = Field(default=None, description="Optional session ID for context")


class TokenUsage(BaseModel):
    """Token usage from an API call."""

    input_tokens: int = Field(default=0, description="Input tokens consumed")
    output_tokens: int = Field(default=0, description="Output tokens generated")
    model: str = Field(default="", description="Model used for generation")

    @property
    def total_tokens(self) -> int:
        """Total tokens consumed."""
        return self.input_tokens + self.output_tokens


class ChatResponse(BaseModel):
    """Response from the chat endpoint."""

    response: str = Field(description="Assistant's response")
    sources: list[dict] = Field(default_factory=list, description="Source documents used")
    usage: Optional[TokenUsage] = Field(default=None, description="Token usage for quota tracking")


class IngestRequest(BaseModel):
    """Request to ingest documents."""

    path: str = Field(description="Path to file or directory")
    doc_type: str = Field(default="project", description="vendor or project")


class IngestResponse(BaseModel):
    """Response from ingestion."""

    status: str = Field(description="success or error")
    documents_ingested: int = Field(default=0)
    chunks_created: int = Field(default=0)
    message: Optional[str] = Field(default=None)


class RAGStats(BaseModel):
    """Statistics about the RAG system."""

    document_count: int
    chunk_count: int
    collection_name: str
