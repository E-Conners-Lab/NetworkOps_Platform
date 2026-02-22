# Memory System

Persistent context and error-learning system that gives MCP tools memory across sessions. Combines SQLite for structured queries with ChromaDB for semantic search, enabling the AI to recall past operations, learn from mistakes, and inject relevant context into future tool calls.

## How It Works

```
Tool Call (e.g., health_check on R1)
     │
     ├──► Pre-hook: Fetch relevant context
     │         ├── SQLite: Recent tool calls, device states
     │         ├── ChromaDB: Semantic search for related history
     │         └── Feedback: Past errors + corrections for this tool/device
     │                │
     │                ▼
     │         [Learned Corrections]
     │           ⚠ send_command on R1 previously failed (connection) → Fix: Run health_check first
     │         [Memory Context]
     │           - [R1] 2025-01-15 14:32: R1 status: healthy
     │                │
     │                ▼
     │         Context injected into tool execution
     │
     ├──► Tool executes
     │
     └──► Post-hook: Record result (fire-and-forget)
               ├── SQLite: tool_name, device, args, result summary, duration, status
               └── ChromaDB: Semantic embedding for future search
```

1. Before each tool call, the `MemoryAwareToolManager` fetches relevant context and learned corrections
2. Context and feedback are formatted and injected into the tool's execution environment
3. After execution, the result is recorded asynchronously (non-blocking)
4. Recorded results become searchable context for future tool calls
5. Feedback from errors is prioritized in future context injection

## Architecture

```
memory/
├── store.py            # MemoryStore: SQLite + ChromaDB dual storage engine
├── context_manager.py  # MemoryAwareToolManager: context injection + pre/post hooks
├── embeddings.py       # EmbeddingService: sentence-transformers with abbreviation expansion
├── models.py           # Pydantic models (ContextItem, ToolCallRecord, FeedbackRecord, etc.)
└── config.py           # MemoryConfig: environment-variable-driven configuration

mcp_tools/
├── memory.py           # 9 MCP tools for memory operations
└── feedback.py         # 4 MCP tools for error learning
```

## Storage

### SQLite (`data/networkops.db`)

Four tables with indexed columns for fast queries:

| Table | Purpose | Key Fields |
|-------|---------|------------|
| `tool_calls` | Every tool invocation | `tool_name`, `device_name`, `arguments`, `result_summary`, `duration_ms`, `status` |
| `device_states` | Device state snapshots | `device_name`, `state_type`, `data`, `label` |
| `conversations` | Conversation summaries | `session_id`, `summary`, `tools_used`, `devices_mentioned` |
| `feedback` | Error learning records | `tool_name`, `device_name`, `correct`, `error_type`, `resolution`, `severity`, `learned` |

Production settings enabled by default: WAL journal mode, `SYNCHRONOUS=NORMAL`, foreign keys enforced.

### ChromaDB (`data/chromadb/`)

Semantic search index using the `network_memory` collection. Tool results, conversation summaries, and feedback resolutions are embedded and indexed for natural language retrieval. Uses cosine similarity search.

Embeddings are generated locally with `sentence-transformers/all-MiniLM-L6-v2` (384 dimensions) — no external API calls.

### Abbreviation Expansion

The `EmbeddingService` automatically expands 26 network abbreviations before embedding to improve semantic matching:

```
OSPF → Open Shortest Path First routing protocol
BGP  → Border Gateway Protocol
DMVPN → Dynamic Multipoint VPN
NHRP → Next Hop Resolution Protocol
EIGRP → Enhanced Interior Gateway Routing Protocol
NETCONF → Network Configuration Protocol
...and 20 more
```

## Context Injection

The `MemoryAwareToolManager` wraps tool execution with pre/post hooks that handle context injection and result recording.

### Relevance Scoring

Context items are ranked by a weighted score combining four factors:

| Factor | Weight | Description |
|--------|--------|-------------|
| Time decay | 30% | Exponential decay with 1-hour half-life |
| Device match | 40% | Same device as the current tool call |
| Tool similarity | 20% | Related tools (e.g., `health_check` ↔ `health_check_all` = 0.9) |
| Semantic score | 10% | ChromaDB cosine similarity |

### Investigative Tools

These tools receive richer context (including semantic search) because they benefit from more background:

`health_check`, `health_check_all`, `full_network_test`, `get_interface_status`, `pyats_diff_state`, `discover_topology`, `get_bgp_neighbors_netconf`, `send_command`

### Error Learning

When a tool fails, recording feedback creates a correction that gets injected into future calls:

```python
# Record an error
await store.record_feedback(
    tool_name="send_command",
    correct=False,
    device_name="R1",
    error_type="connection",
    original_error="Connection refused on port 22",
    resolution="Run health_check first to verify device is reachable",
    severity="high"
)

# Next time send_command runs on R1, the pre-hook injects:
# [Learned Corrections]
#   ⚠ [HIGH] send_command on R1. previously failed (connection) → Fix: Run health_check first
```

Feedback is prioritized by relevance:
1. Same tool + same device + same error type (highest)
2. Same tool + same device
3. Same tool + same error type
4. Same tool (lowest)

## MCP Tools

### Memory Tools (9)

| Tool | Description |
|------|-------------|
| `memory_search` | Search memory with natural language query |
| `memory_save` | Save a note to memory for later retrieval |
| `memory_recall_device` | Get recent events for a specific device (last 24h) |
| `memory_stats` | Get memory system statistics |
| `memory_context` | Preview what context would be injected for a tool call |
| `memory_backup` | Create a backup of the SQLite database |
| `memory_prune` | Prune old records by age and count limits |
| `memory_repair` | Run integrity check, reindex, and vacuum |
| `memory_maintenance` | Run full maintenance (prune + vacuum) |

### Feedback Tools (4)

| Tool | Description |
|------|-------------|
| `feedback_record` | Record whether a tool action was correct or incorrect |
| `feedback_search` | Search for past errors/corrections for a tool |
| `feedback_stats` | Get error patterns by tool and error type |
| `feedback_learn` | Mark a feedback record as learned/incorporated |

## Usage

### Via MCP Tools

```bash
# Search memory for past OSPF issues
memory_search("NHRP tunnel problems")

# Save a note for future sessions
memory_save("R3 BGP peering to edge1 requires keepalive tuning", devices="R3,edge1", topics="BGP,troubleshooting")

# Get recent events for a device
memory_recall_device("R1")

# Preview context injection
memory_context("health_check", device_name="R1")

# Record an error for learning
feedback_record("send_command", correct=False, device_name="R1",
    error_type="timeout", original_error="Command timed out after 30s",
    resolution="Increase timeout to 60s for show tech-support")

# Check error patterns
feedback_stats(days=7)
```

### Via Python

```python
from memory import MemoryStore, MemoryAwareToolManager

# Initialize
store = MemoryStore()
await store.initialize()  # Runs auto-pruning if configured

manager = MemoryAwareToolManager(store)

# Record a tool call
await store.record_tool_call(
    tool_name="health_check",
    device_name="R1",
    result_summary="R1 status: healthy",
    duration_ms=342,
    status="success"
)

# Save a device state snapshot
await store.record_device_state(
    device_name="R1",
    state_type="baseline",
    data={"cpu": 12, "memory": 45, "uptime": "3d 14h"},
    label="pre-maintenance"
)

# Semantic search
results = await store.semantic_search("DMVPN tunnel flapping")
for item in results:
    print(f"[{item.device}] {item.content} (score: {item.semantic_score:.2f})")

# Get context for a tool call
context = await manager.get_context_for_tool("health_check", {"device_name": "R1"})
feedback = await manager.get_feedback_for_tool("health_check", "R1")
display = manager.format_context_for_injection(context, feedback)

# Maintenance
await store.run_maintenance()  # Prune by age + count, then vacuum
backup_path = await store.backup()  # SQLite backup API
```

## Retention & Maintenance

Retention is enforced two ways:

- **By age** — records older than `retention_days` are deleted
- **By count** — each table is capped at a maximum number of records (oldest pruned first)

Maintenance runs automatically on startup if `auto_prune_on_startup` is enabled (default). You can also trigger it manually via `memory_maintenance` or `store.run_maintenance()`.

### Backup & Recovery

```python
# Create backup (uses SQLite's backup API for consistency)
backup_path = await store.backup()
# Backups go to data/backups/memory_YYYYMMDD_HHMMSS.db
# Old backups auto-cleaned (keeps last 5 by default)

# Check integrity
is_ok, message = await store.check_integrity()

# Repair (reindex + vacuum)
results = await store.repair()
```

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `MEMORY_RETENTION_DAYS` | Delete records older than N days (0 = disabled) | `30` |
| `MEMORY_MAX_TOOL_CALLS` | Maximum tool_calls records | `5000` |
| `MEMORY_MAX_CONVERSATIONS` | Maximum conversation records | `1000` |
| `MEMORY_MAX_DEVICE_STATES` | Maximum device_state records | `1000` |
| `MEMORY_MAX_CHROMADB_DOCS` | Maximum semantic index documents | `5000` |
| `MEMORY_BACKUP_DIR` | Backup file directory | `data/backups` |
| `MEMORY_MAX_BACKUPS` | Backup files to retain | `5` |
| `MEMORY_CONTEXT_LIMIT` | Max context items injected per tool call | `5` |
| `MEMORY_TIME_WINDOW_MINUTES` | How far back to search for context | `60` |
| `MEMORY_ENABLE_SEMANTIC` | Enable ChromaDB semantic search | `true` |
| `MEMORY_AUTO_PRUNE` | Run pruning on startup | `true` |
