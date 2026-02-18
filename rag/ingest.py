"""
Document ingestion for RAG system.

Handles:
- PDF parsing with PyMuPDF
- HTML parsing with BeautifulSoup
- Text chunking with overlap
- Storage in ChromaDB
"""

import hashlib
import logging
import os
from core.timestamps import now
from pathlib import Path
from typing import Optional

from bs4 import BeautifulSoup

from .models import DocumentChunk, IngestResponse
from core.chromadb_client import get_chromadb_client, get_documentation_collection

# Configure logger
logger = logging.getLogger(__name__)

# Default chunk settings
DEFAULT_CHUNK_SIZE = int(os.getenv("RAG_CHUNK_SIZE", "500"))
DEFAULT_CHUNK_OVERLAP = int(os.getenv("RAG_CHUNK_OVERLAP", "50"))


class DocumentIngestor:
    """Handles document parsing and storage in ChromaDB."""

    COLLECTION_NAME = "documentation"

    def __init__(
        self,
        chromadb_path: Optional[Path] = None,
        chunk_size: int = DEFAULT_CHUNK_SIZE,
        chunk_overlap: int = DEFAULT_CHUNK_OVERLAP,
    ):
        """
        Initialize the document ingestor.

        Args:
            chromadb_path: Path to ChromaDB storage directory
            chunk_size: Target size for text chunks (in characters)
            chunk_overlap: Overlap between consecutive chunks
        """
        self.chunk_size = chunk_size
        self.chunk_overlap = chunk_overlap

        # Initialize ChromaDB using core module
        self._client = get_chromadb_client(chromadb_path)
        self._collection = get_documentation_collection(chromadb_path)

        # Lazy-load embedding service
        self._embedding_service = None

    def _get_embedding_service(self):
        """Lazy-load the embedding service."""
        if self._embedding_service is None:
            # Import from existing memory module
            import sys
            sys.path.insert(0, str(Path(__file__).parent.parent))
            from memory.embeddings import EmbeddingService
            self._embedding_service = EmbeddingService()
        return self._embedding_service

    def _generate_chunk_id(self, source_file: str, chunk_index: int) -> str:
        """Generate a unique ID for a chunk."""
        content = f"{source_file}:{chunk_index}"
        return hashlib.md5(content.encode(), usedforsecurity=False).hexdigest()[:16]

    def chunk_text(self, text: str) -> list[str]:
        """
        Split text into overlapping chunks.

        Uses sentence boundaries when possible for cleaner chunks.
        """
        if not text or len(text) <= self.chunk_size:
            return [text] if text else []

        chunks = []
        start = 0

        while start < len(text):
            # Calculate end position
            end = start + self.chunk_size

            # If not at the end, try to break at a sentence boundary
            if end < len(text):
                # Look for sentence endings
                for sep in [". ", ".\n", "! ", "!\n", "? ", "?\n", "\n\n"]:
                    last_sep = text.rfind(sep, start, end)
                    if last_sep > start:
                        end = last_sep + len(sep)
                        break

            chunk = text[start:end].strip()
            if chunk:
                chunks.append(chunk)

            # Move start position with overlap
            # IMPORTANT: Ensure we always advance by at least 1 character to prevent infinite loops
            new_start = end - self.chunk_overlap
            start = max(new_start, start + 1)

        return chunks

    def parse_pdf(self, file_path: str) -> list[DocumentChunk]:
        """
        Parse a PDF file into document chunks.

        Args:
            file_path: Path to the PDF file

        Returns:
            List of DocumentChunk objects
        """
        import fitz  # PyMuPDF

        chunks = []
        path = Path(file_path)

        try:
            doc = fitz.open(file_path)
            logger.info(f"Parsing PDF: {path.name} ({len(doc)} pages)")

            for page_num, page in enumerate(doc, 1):
                text = page.get_text()
                if not text.strip():
                    continue

                # Chunk the page text
                page_chunks = self.chunk_text(text)

                for i, chunk_text in enumerate(page_chunks):
                    chunk = DocumentChunk(
                        id=self._generate_chunk_id(file_path, len(chunks)),
                        content=chunk_text,
                        source_file=str(path),
                        page_number=page_num,
                        chunk_index=len(chunks),
                        doc_type="vendor",  # Will be overridden by caller if needed
                        timestamp=now(),
                    )
                    chunks.append(chunk)

            doc.close()
            logger.info(f"Created {len(chunks)} chunks from {path.name}")

        except Exception as e:
            logger.error(f"Error parsing PDF {file_path}: {e}")
            raise

        return chunks

    def parse_html(self, file_path: str) -> list[DocumentChunk]:
        """
        Parse an HTML file into document chunks.

        Args:
            file_path: Path to the HTML file

        Returns:
            List of DocumentChunk objects
        """
        chunks = []
        path = Path(file_path)

        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                html_content = f.read()

            soup = BeautifulSoup(html_content, "lxml")

            # Remove script and style elements
            for element in soup(["script", "style", "nav", "footer", "header"]):
                element.decompose()

            # Extract text
            text = soup.get_text(separator="\n", strip=True)

            if not text:
                logger.warning(f"No text extracted from {path.name}")
                return []

            logger.info(f"Parsing HTML: {path.name} ({len(text)} chars)")

            # Chunk the text
            text_chunks = self.chunk_text(text)

            for i, chunk_text in enumerate(text_chunks):
                chunk = DocumentChunk(
                    id=self._generate_chunk_id(file_path, i),
                    content=chunk_text,
                    source_file=str(path),
                    page_number=None,
                    chunk_index=i,
                    doc_type="project",  # Will be overridden by caller if needed
                    timestamp=now(),
                )
                chunks.append(chunk)

            logger.info(f"Created {len(chunks)} chunks from {path.name}")

        except Exception as e:
            logger.error(f"Error parsing HTML {file_path}: {e}")
            raise

        return chunks

    def ingest_file(self, file_path: str, doc_type: str = "project") -> IngestResponse:
        """
        Ingest a single file (PDF or HTML).

        Args:
            file_path: Path to the file
            doc_type: Document type ("vendor" or "project")

        Returns:
            IngestResponse with status
        """
        path = Path(file_path)

        if not path.exists():
            return IngestResponse(
                status="error",
                message=f"File not found: {file_path}"
            )

        suffix = path.suffix.lower()

        try:
            if suffix == ".pdf":
                chunks = self.parse_pdf(file_path)
            elif suffix in [".html", ".htm"]:
                chunks = self.parse_html(file_path)
            else:
                return IngestResponse(
                    status="error",
                    message=f"Unsupported file type: {suffix}"
                )

            # Set doc_type for all chunks
            for chunk in chunks:
                chunk.doc_type = doc_type

            # Store in ChromaDB
            if chunks:
                self._store_chunks(chunks)

            return IngestResponse(
                status="success",
                documents_ingested=1,
                chunks_created=len(chunks),
                message=f"Ingested {path.name}"
            )

        except Exception as e:
            logger.error(f"Error ingesting {file_path}: {e}")
            return IngestResponse(
                status="error",
                message=str(e)
            )

    def ingest_directory(
        self,
        dir_path: str,
        doc_type: str = "project",
        recursive: bool = True
    ) -> IngestResponse:
        """
        Ingest all PDF and HTML files in a directory.

        Args:
            dir_path: Path to the directory
            doc_type: Document type for all files
            recursive: Whether to search subdirectories

        Returns:
            IngestResponse with totals
        """
        path = Path(dir_path)

        if not path.exists():
            return IngestResponse(
                status="error",
                message=f"Directory not found: {dir_path}"
            )

        if not path.is_dir():
            return IngestResponse(
                status="error",
                message=f"Not a directory: {dir_path}"
            )

        total_docs = 0
        total_chunks = 0
        errors = []

        # Find all PDF and HTML files
        patterns = ["*.pdf", "*.html", "*.htm"]
        files = []
        for pattern in patterns:
            if recursive:
                files.extend(path.rglob(pattern))
            else:
                files.extend(path.glob(pattern))

        logger.info(f"Found {len(files)} files to ingest in {dir_path}")

        for file_path in files:
            result = self.ingest_file(str(file_path), doc_type)
            if result.status == "success":
                total_docs += result.documents_ingested
                total_chunks += result.chunks_created
            else:
                errors.append(f"{file_path.name}: {result.message}")

        status = "success" if not errors else "partial"
        message = None
        if errors:
            message = f"Errors: {'; '.join(errors[:5])}"
            if len(errors) > 5:
                message += f" (+{len(errors) - 5} more)"

        return IngestResponse(
            status=status,
            documents_ingested=total_docs,
            chunks_created=total_chunks,
            message=message
        )

    def _store_chunks(self, chunks: list[DocumentChunk]) -> None:
        """Store chunks in ChromaDB with embeddings."""
        if not chunks:
            return

        embedding_service = self._get_embedding_service()

        # ChromaDB has a max batch size limit (~5000)
        BATCH_SIZE = 1000  # Conservative batch size for stability

        total_stored = 0
        for i in range(0, len(chunks), BATCH_SIZE):
            batch = chunks[i:i + BATCH_SIZE]
            texts = [chunk.content for chunk in batch]

            # Run async embedding in sync context
            from core.async_utils import run_sync
            embeddings = run_sync(
                embedding_service.embed_batch(texts, preprocess=True)
            )

            # Prepare data for ChromaDB
            ids = [chunk.id for chunk in batch]
            metadatas = [
                {
                    "source_file": chunk.source_file,
                    "page_number": chunk.page_number or -1,
                    "chunk_index": chunk.chunk_index,
                    "doc_type": chunk.doc_type,
                    "timestamp": chunk.timestamp.isoformat(),
                }
                for chunk in batch
            ]

            # Upsert to handle duplicates
            self._collection.upsert(
                ids=ids,
                embeddings=embeddings,
                documents=texts,
                metadatas=metadatas,
            )

            total_stored += len(batch)
            logger.info(f"Stored batch {i // BATCH_SIZE + 1}: {len(batch)} chunks (total: {total_stored})")

        logger.info(f"Stored {total_stored} chunks in ChromaDB")

    def get_stats(self) -> dict:
        """Get statistics about the document collection."""
        count = self._collection.count()
        return {
            "collection_name": self.COLLECTION_NAME,
            "chunk_count": count,
            "document_count": count,  # Approximation - could track unique source_files
        }

    def clear_collection(self) -> None:
        """Clear all documents from the collection."""
        self._client.delete_collection(self.COLLECTION_NAME)
        self._collection = get_documentation_collection()
        logger.info("Cleared documentation collection")
