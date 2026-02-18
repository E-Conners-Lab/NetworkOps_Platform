"""
ChromaDB client management.

Consolidates ChromaDB initialization patterns previously duplicated across:
- rag/ingest.py
- rag/query.py
- memory/store.py

Provides centralized path management and collection access.

Usage:
    from core.chromadb_client import (
        get_chromadb_client,
        get_collection,
        CHROMADB_PATH,
    )

    # Get client for custom operations
    client = get_chromadb_client()

    # Get a collection (creates if doesn't exist)
    collection = get_collection("documentation", "RAG documentation")
"""

from pathlib import Path
from typing import Optional

import chromadb
from chromadb import PersistentClient
from chromadb.api.models.Collection import Collection


# Default paths
PROJECT_ROOT = Path(__file__).parent.parent
CHROMADB_PATH = PROJECT_ROOT / "data" / "chromadb"

# Known collection names
COLLECTION_DOCUMENTATION = "documentation"
COLLECTION_MEMORY = "network_memory"

# Singleton client instance
_client: Optional[PersistentClient] = None


def get_chromadb_client(path: Optional[Path] = None) -> PersistentClient:
    """
    Get or create a ChromaDB persistent client.

    Args:
        path: Optional custom path. If None, uses default CHROMADB_PATH.
              Note: Only the first call's path is used (singleton pattern).

    Returns:
        ChromaDB PersistentClient instance
    """
    global _client

    if _client is None:
        chromadb_path = path or CHROMADB_PATH
        chromadb_path.mkdir(parents=True, exist_ok=True)
        _client = chromadb.PersistentClient(path=str(chromadb_path))

    return _client


def get_collection(
    name: str,
    description: Optional[str] = None,
    path: Optional[Path] = None,
) -> Collection:
    """
    Get or create a ChromaDB collection.

    Args:
        name: Collection name
        description: Optional description for metadata
        path: Optional custom ChromaDB path

    Returns:
        ChromaDB Collection instance

    Example:
        # Get the documentation collection
        docs = get_collection("documentation", "RAG documentation")

        # Get the memory collection
        memory = get_collection("network_memory", "Network automation memory")
    """
    client = get_chromadb_client(path)

    metadata = {}
    if description:
        metadata["description"] = description

    return client.get_or_create_collection(
        name=name,
        metadata=metadata if metadata else None,
    )


def get_documentation_collection(path: Optional[Path] = None) -> Collection:
    """
    Get the documentation collection for RAG.

    Convenience function for the most common use case.
    """
    return get_collection(
        COLLECTION_DOCUMENTATION,
        "Documentation for RAG chatbot",
        path,
    )


def get_memory_collection(path: Optional[Path] = None) -> Collection:
    """
    Get the network memory collection.

    Convenience function for memory system.
    """
    return get_collection(
        COLLECTION_MEMORY,
        "Network automation memory",
        path,
    )


def reset_client() -> None:
    """
    Reset the singleton client.

    Useful for testing or when changing paths.
    """
    global _client
    _client = None
