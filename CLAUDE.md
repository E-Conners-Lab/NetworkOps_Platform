# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

NetworkOps is an AI-powered network automation platform with two primary entry points:
1. **MCP Server** (`network_mcp_async.py`) — 178 tools for Claude integration
2. **Dashboard** (`dashboard/api_server.py`) — Flask REST API + React 19 frontend + gRPC telemetry

## Common Commands

```bash
# Setup
cp .env.example .env                    # Configure environment
uv venv --python 3.11                   # Create venv (downloads Python 3.11 if needed)
source .venv/bin/activate
uv pip install -r requirements.txt      # Install dependencies (or: pip install -r requirements.txt)
alembic upgrade head                    # Run database migrations

# Run
python dashboard/api_server.py          # Dashboard API (port 5001)
# For MCP: configure in Claude Desktop / claude_desktop_config.json

# Tests
pytest tests/ -v                        # All tests
pytest tests/test_api_contracts.py -v   # Fast API contract tests (no lab needed)
pytest tests/test_some_file.py::TestClass::test_method -v  # Single test
pytest -m "not slow"                    # Skip slow tests
pytest -m unit                          # Unit tests only
SKIP_DEVICE_TESTS=true pytest           # Skip tests requiring live devices

# Linting
ruff check .                            # Lint
ruff check . --fix                      # Lint with auto-fix
ruff format .                           # Format

# Pre-commit
pre-commit install                      # Install hooks
pre-commit run --all-files              # Run all hooks

# Docker
docker-compose up -d                    # Dev environment
docker-compose -f docker-compose.prod.yml up -d  # Production
```

## Architecture

### Core (`core/`) — 230+ modules
The engine layer. Key subsystems:
- **Network engines**: `impact_analyzer.py`, `dependency_graph.py`, `compliance_engine.py`, `bgp_discovery.py`
- **Device connectivity**: `connection_pool.py`, `device_cache.py`, `containerlab.py`, `eve_ng_client.py`
- **Automation**: `ansible_manager.py`, `nornir_manager.py`, `aetest_runner.py`
- **Config management**: `config_tree.py`, `config_tree_db.py`, `config_tree_generator.py`
- **Data layer**: `unified_db.py` (singleton, thread-safe), `db.py`, `event_logger.py`

### Dashboard (`dashboard/`)
- `app.py` — Flask application factory (`create_app()`)
- `api_server.py` — Entry point (Flask + MDT gRPC port 57000 + WebSocket)
- `routes/` — 18+ Flask blueprints with per-endpoint rate limiting
- `auth/` — JWT (HS256), MFA/TOTP, RBAC (Admin/Operator/Viewer)
- `src/` — React 19 TypeScript frontend (served from `build/`)

### MCP Tools (`mcp_tools/`)
- 20 modules, 178 tools across 24 categories
- Registered centrally in `__init__.py` with duplicate detection
- Wrapped with auth enforcement + metrics tracking

### Memory System (`memory/`)
ChromaDB-backed semantic search with sentence-transformers embeddings.

### RAG Chatbot (`rag/`)
Claude API with tool-calling for live network queries mid-conversation.

### Supporting
- `config/` — Device inventory, Vault client, credential management
- `security/` — Auth, RBAC, command policy (blocks dangerous commands like `reload`, `write erase`)
- `templates/` — Jinja2 config templates (FRR, IOS-XE)
- `alembic/` — Database migrations (SQLite default, PostgreSQL optional)

## Key Patterns

- **Application Factory**: `create_app()` in `dashboard/app.py` — all Flask setup flows through here
- **Singleton Managers**: `UnifiedDB`, `DatabaseManager`, `MemoryStore`, `EventLogger` — use `.get_instance()`
- **Database**: Raw SQL via DB-API 2.0 (not an ORM). SQLite default (`data/networkops.db`), PostgreSQL via `DATABASE_URL`
- **Credentials**: Lazy-loaded from HashiCorp Vault with `.env` fallback, TTL-based cache (5min default)
- **Async throughout**: FastMCP async server, asyncio+scrapli for SSH, async NETCONF
- **DEMO_MODE**: Set `DEMO_MODE=true` in `.env` to run without real network devices
- **Containerlab execution**: All containerlab commands flow through `_build_exec_command()` in `core/containerlab.py`. Set `CONTAINERLAB_LOCAL=true` to run Docker commands directly (bare-metal/VM), or leave `false` to route through Multipass

## Testing Notes

- `pytest.ini` sets `pythonpath = .` and `asyncio_mode = auto`
- `tests/conftest.py` provides mock fixtures for scrapli, ncclient, containerlab, and resets DB singletons between tests
- Markers: `slow`, `integration` (live devices), `unit`
- CI runs `test_api_contracts.py` (fast, no lab) and lab tests on self-hosted runner

## Linting Config

- **ruff.toml**: Ignores F401, F841, F541, E402, E741. Excludes test files.
- **Pre-commit hooks**: ruff (lint+format), mypy (only `agents/` dir), bandit (security), YAML validation
- Pre-commit blocks direct commits to `main`/`master` (`no-commit-to-branch` hook)

## Supported Network Platforms

Cisco IOS-XE (NETCONF + SSH + pyATS), Cisco IOS (SSH), FRRouting (containerlab), Nokia SR Linux (containerlab), Linux/Alpine hosts. pyATS requires Python 3.11.
