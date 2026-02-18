"""
Core shared utilities for the network lab project.

This module consolidates common functionality used across:
- network_mcp_async.py (MCP server)
- dashboard/api_server.py (Flask API)
- rag/ module (RAG chatbot)
"""

from .event_logger import (
    EventLogger,
    event_logger,
    log_event,
    load_event_log,
    save_event_log,
    get_event_log,
    clear_event_log,
)

from .containerlab import (
    run_command as containerlab_run_command,
    check_health as containerlab_check_health,
    check_health_status as containerlab_check_health_status,
    get_container_stats as containerlab_get_stats,
)

from .async_utils import run_sync, try_create_task

# Optional imports - these require heavy dependencies that may not be installed
# in minimal test environments (e.g., CI API contract tests)
try:
    from .scrapli_manager import (
        get_ios_xe_connection,
        get_linux_connection,
        send_command as scrapli_send_command,
        send_commands as scrapli_send_commands,
        send_config as scrapli_send_config,
    )
except ImportError:
    # Scrapli not installed - provide stub functions
    get_ios_xe_connection = None
    get_linux_connection = None
    scrapli_send_command = None
    scrapli_send_commands = None
    scrapli_send_config = None

try:
    from .netconf_client import (
        get_netconf_connection,
        netconf_connect,
        netconf_get,
        netconf_get_capabilities,
    )
except ImportError:
    # ncclient not installed
    get_netconf_connection = None
    netconf_connect = None
    netconf_get = None
    netconf_get_capabilities = None

try:
    from .chromadb_client import (
        get_chromadb_client,
        get_collection,
        get_documentation_collection,
        get_memory_collection,
        CHROMADB_PATH,
    )
except ImportError:
    # chromadb not installed
    get_chromadb_client = None
    get_collection = None
    get_documentation_collection = None
    get_memory_collection = None
    CHROMADB_PATH = None

__all__ = [
    # Event logging
    "EventLogger",
    "event_logger",
    "log_event",
    "load_event_log",
    "save_event_log",
    "get_event_log",
    "clear_event_log",
    # Containerlab
    "containerlab_run_command",
    "containerlab_check_health",
    "containerlab_check_health_status",
    "containerlab_get_stats",
    # Async utilities
    "run_sync",
    "try_create_task",
    # Scrapli SSH
    "get_ios_xe_connection",
    "get_linux_connection",
    "scrapli_send_command",
    "scrapli_send_commands",
    "scrapli_send_config",
    # NETCONF
    "get_netconf_connection",
    "netconf_connect",
    "netconf_get",
    "netconf_get_capabilities",
    # ChromaDB
    "get_chromadb_client",
    "get_collection",
    "get_documentation_collection",
    "get_memory_collection",
    "CHROMADB_PATH",
]
