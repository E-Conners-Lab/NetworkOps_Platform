# RAG Chatbot

AI-powered documentation assistant that combines semantic search over your own documents with live network device queries via Claude.

## How It Works

```
User Question
     │
     ├──► Embed query (sentence-transformers, local)
     │         │
     │         ▼
     │    ChromaDB semantic search ──► Top-K document chunks
     │                                       │
     ├───────────────────────────────────────►│
     │                                       ▼
     │                              Claude API call with:
     │                                • Document context
     │                                • Network tools (optional)
     │                                • Conversation history
     │                                       │
     │                              ◄── tool_use loop ──►
     │                              (execute show commands,
     │                               health checks, etc.)
     │                                       │
     ▼                                       ▼
Response with source citations + live device data
```

1. Your question is embedded locally using `all-MiniLM-L6-v2` (no API call)
2. ChromaDB returns the most relevant document chunks via cosine similarity
3. Claude receives the chunks as context alongside your question
4. If live network data is needed, Claude calls tools (show commands, health checks) in an agentic loop
5. The response includes source citations (file, page, relevance score) and any live tool results

## Ingesting Your Own Documents

### Supported Formats

| Format | Parser | Notes |
|--------|--------|-------|
| `.pdf` | PyMuPDF (fitz) | Page numbers tracked in metadata |
| `.html` / `.htm` | BeautifulSoup (lxml) | Scripts, styles, nav, footer, header stripped |

### Via the Dashboard API (Recommended)

Requires admin credentials. Paths must be within the project directory.

```bash
# Get a token
TOKEN=$(curl -s -X POST http://localhost:5001/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin"}' | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])")

# Ingest a single PDF
curl -X POST http://localhost:5001/api/ingest \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"path": "/absolute/path/to/document.pdf", "doc_type": "vendor"}'

# Ingest an entire directory (recursive)
curl -X POST http://localhost:5001/api/ingest \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"path": "/absolute/path/to/docs/", "doc_type": "project"}'
```

**Response:**
```json
{
  "status": "success",
  "documents_ingested": 3,
  "chunks_created": 247,
  "message": null
}
```

### Via Python

```python
from rag.ingest import DocumentIngestor

ingestor = DocumentIngestor()

# Single file
result = ingestor.ingest_file("/path/to/cisco-guide.pdf", doc_type="vendor")
print(f"Created {result.chunks_created} chunks")

# Entire directory (finds all .pdf and .html files recursively)
result = ingestor.ingest_directory("/path/to/docs/", doc_type="project")
print(f"Ingested {result.documents_ingested} files, {result.chunks_created} chunks")

# Check what's in the collection
stats = ingestor.get_stats()
print(f"Total chunks: {stats['chunk_count']}")

# Start over
ingestor.clear_collection()
```

### Document Types

Use `doc_type` to tag documents by origin:

- **`vendor`** — Manufacturer documentation (Cisco config guides, Juniper TechLibrary, RFCs, etc.)
- **`project`** — Your own documentation (runbooks, SOPs, topology notes, internal wikis)

This metadata is stored alongside each chunk and can be used for filtering.

### Chunking

Documents are split into overlapping chunks for embedding:

- **Chunk size**: 500 characters (configurable via `RAG_CHUNK_SIZE`)
- **Overlap**: 50 characters (configurable via `RAG_CHUNK_OVERLAP`)
- Breaks at sentence boundaries (`. `, `? `, `! `, `\n\n`) when possible
- Duplicate chunks are handled via upsert (re-ingesting the same file is safe)

### Tips for Good Results

- **PDF quality matters** — scanned images without OCR won't extract text. Use text-based PDFs.
- **Chunk size tuning** — increase `RAG_CHUNK_SIZE` for documents with long, context-dependent passages (e.g., troubleshooting guides). Decrease for reference material with short, self-contained entries.
- **Batch large collections** — `ingest_directory` processes files sequentially and handles partial failures (returns `"status": "partial"` with error details).
- **Network abbreviations are expanded** during embedding — the system automatically expands acronyms like OSPF, BGP, DMVPN, VLAN, etc. into their full forms to improve search quality.

## Querying

### Via the Dashboard Chat Panel

The dashboard includes a chat interface that connects to the RAG system. All authenticated users can query; tool access is permission-based:

- **Read-only users** — documentation search + show commands + health checks
- **Admin users** — all of the above + send config commands + interface remediation

### Via the API

```bash
# Simple question (uses RAG + network tools)
curl -X POST http://localhost:5001/api/chat \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"message": "What is the OSPF cost formula for Ethernet interfaces?"}'

# With model selection and conversation history
curl -X POST http://localhost:5001/api/chat \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "message": "Show me the current OSPF neighbors on R1",
    "model": "claude-sonnet-4-20250514",
    "history": [
      {"role": "user", "content": "What routers are in the lab?"},
      {"role": "assistant", "content": "The lab has R1-R4 (IOS-XE), Switch-R1/R2/R4, and Linux hosts."}
    ]
  }'
```

**Response:**
```json
{
  "response": "Based on the live data from R1...",
  "sources": [
    {"file": "ospf-design-guide.pdf", "path": "/docs/ospf-design-guide.pdf", "page": 12, "score": 0.847},
    {"file": "[Live] send_command", "path": "network_tool", "page": null, "score": 1.0, "tool_input": {"device_name": "R1", "command": "show ip ospf neighbor"}}
  ],
  "usage": {"input_tokens": 1523, "output_tokens": 384, "total_tokens": 1907, "model": "claude-sonnet-4-20250514"},
  "status": "success"
}
```

### Via Python

```python
from rag.query import RAGQueryEngine

engine = RAGQueryEngine()

# Documentation-only search
results = engine.search("DMVPN phase 3 spoke-to-spoke")
for r in results:
    print(f"[{r.score:.3f}] {r.chunk.source_file} p.{r.chunk.page_number}")
    print(f"  {r.chunk.content[:100]}...")

# Generate a response with Claude
response = engine.generate_response("How does NHRP resolution work in DMVPN?")
print(response.response)
print("Sources:", response.sources)

# Full chat with network tools
response = engine.chat(
    "Is R1's OSPF adjacency with R2 up?",
    permissions=["run_config_commands"],
    conversation_history=[...]
)
```

## Architecture

```
rag/
├── ingest.py          # Document parsing (PDF, HTML) and ChromaDB storage
├── query.py           # Semantic search + Claude response generation + tool loop
├── network_tools.py   # Live device tools (show commands, health, config, remediation)
├── models.py          # Pydantic models (DocumentChunk, ChatResponse, TokenUsage, etc.)
└── sanitizer.py       # Prompt injection detection + input validation
```

### Network Tools Available in Chat

| Tool | Permission | Description |
|------|-----------|-------------|
| `get_devices` | — | List all lab devices |
| `health_check` | — | Device connectivity check |
| `send_command` | — | Execute show commands (read-only enforced) |
| `get_interface_status` | — | Interface details |
| `get_hierarchy` | — | NetBox region/site/rack tree |
| `get_device_location` | — | Physical device location |
| `get_netbox_ips` | — | IP addresses from IPAM |
| `send_config` | `run_config_commands` | Send configuration commands |
| `remediate_interface` | `remediate_interfaces` | Shutdown/no-shutdown/bounce |

## Security

- **Prompt injection detection** — user queries and conversation history are scanned for injection patterns (XML injection, ChatML, instruction override attempts)
- **Indirect injection protection** — document chunks are sanitized before being added to the Claude prompt, preventing malicious content in ingested documents from hijacking the model
- **Path traversal prevention** — the `/api/ingest` endpoint restricts paths to the project directory
- **Model whitelist** — only approved Claude models can be selected
- **Input limits** — queries max 2,000 chars; history max 20 messages at 4,000 chars each

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `ANTHROPIC_API_KEY` | Claude API key (required for chat) | — |
| `RAG_CHUNK_SIZE` | Characters per chunk | `500` |
| `RAG_CHUNK_OVERLAP` | Overlap between chunks | `50` |
| `RAG_TOP_K` | Search results returned per query | `5` |
| `CHAT_MONTHLY_TOKEN_QUOTA` | Monthly token limit per organization | `1000000` |
| `QUOTA_ENFORCEMENT_ENABLED` | Enable/disable quota enforcement | `true` |

## API Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `POST` | `/api/chat` | JWT | Query the RAG chatbot |
| `POST` | `/api/ingest` | Admin | Ingest documents |
| `GET` | `/api/rag/stats` | JWT | Collection statistics |
| `GET` | `/api/usage` | JWT | Token usage and quota status |

## Data Storage

Documents are stored in ChromaDB at `data/chromadb/` using cosine similarity search. Embeddings are generated locally with `sentence-transformers/all-MiniLM-L6-v2` (384 dimensions) — no external API calls are made for embedding. The model downloads automatically on first use and is cached locally.
