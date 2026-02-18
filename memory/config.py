"""
Memory system configuration with environment variable support.
"""

import os
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class MemoryConfig:
    """
    Configuration for the MCP Memory System.

    All settings can be overridden via environment variables prefixed with MEMORY_.
    """

    # Retention settings
    retention_days: int = 30
    """Delete records older than this many days. Set to 0 to disable."""

    max_tool_calls: int = 5000
    """Maximum tool_calls records to keep. Oldest are pruned first."""

    max_conversations: int = 1000
    """Maximum conversation records to keep."""

    max_device_states: int = 1000
    """Maximum device_state records to keep."""

    max_chromadb_docs: int = 5000
    """Maximum documents in ChromaDB semantic index."""

    # Backup settings
    backup_dir: Path = field(default_factory=lambda: Path("data/backups"))
    """Directory for backup files."""

    max_backups: int = 5
    """Number of backup files to retain."""

    # Performance settings
    context_limit: int = 5
    """Maximum context items to inject per tool call."""

    time_window_minutes: int = 60
    """How far back to look for context (in minutes)."""

    # Feature flags
    enable_semantic: bool = True
    """Enable ChromaDB semantic search."""

    auto_prune_on_startup: bool = True
    """Run retention pruning when MemoryStore initializes."""

    @classmethod
    def from_env(cls) -> "MemoryConfig":
        """
        Create configuration from environment variables.

        Environment variables:
            MEMORY_RETENTION_DAYS: int (default: 30)
            MEMORY_MAX_TOOL_CALLS: int (default: 5000)
            MEMORY_MAX_CONVERSATIONS: int (default: 1000)
            MEMORY_MAX_DEVICE_STATES: int (default: 1000)
            MEMORY_MAX_CHROMADB_DOCS: int (default: 5000)
            MEMORY_BACKUP_DIR: str (default: "data/backups")
            MEMORY_MAX_BACKUPS: int (default: 5)
            MEMORY_CONTEXT_LIMIT: int (default: 5)
            MEMORY_TIME_WINDOW_MINUTES: int (default: 60)
            MEMORY_ENABLE_SEMANTIC: bool (default: true)
            MEMORY_AUTO_PRUNE: bool (default: true)
        """
        def get_int(key: str, default: int) -> int:
            val = os.environ.get(f"MEMORY_{key}")
            if val is None:
                return default
            try:
                return int(val)
            except ValueError:
                return default

        def get_bool(key: str, default: bool) -> bool:
            val = os.environ.get(f"MEMORY_{key}")
            if val is None:
                return default
            return val.lower() in ("true", "1", "yes", "on")

        def get_path(key: str, default: Path) -> Path:
            val = os.environ.get(f"MEMORY_{key}")
            if val is None:
                return default
            return Path(val)

        return cls(
            retention_days=get_int("RETENTION_DAYS", 30),
            max_tool_calls=get_int("MAX_TOOL_CALLS", 5000),
            max_conversations=get_int("MAX_CONVERSATIONS", 1000),
            max_device_states=get_int("MAX_DEVICE_STATES", 1000),
            max_chromadb_docs=get_int("MAX_CHROMADB_DOCS", 5000),
            backup_dir=get_path("BACKUP_DIR", Path("data/backups")),
            max_backups=get_int("MAX_BACKUPS", 5),
            context_limit=get_int("CONTEXT_LIMIT", 5),
            time_window_minutes=get_int("TIME_WINDOW_MINUTES", 60),
            enable_semantic=get_bool("ENABLE_SEMANTIC", True),
            auto_prune_on_startup=get_bool("AUTO_PRUNE", True),
        )


# Global config instance (lazy-loaded from environment)
_config: MemoryConfig | None = None


def get_config() -> MemoryConfig:
    """Get the global memory configuration, loading from env if needed."""
    global _config
    if _config is None:
        _config = MemoryConfig.from_env()
    return _config


def reset_config() -> None:
    """Reset config to force reload from environment (useful for testing)."""
    global _config
    _config = None
