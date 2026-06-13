# ADR-0001: Modular tool registry

- Status: Accepted
- Date: 2026-06-12

## Context

The platform exposes a large MCP tool surface across many domains: device operations, config, diagnostics, NetBox, compliance, capacity, orchestration, and more. Defining all of those in one file does not scale, and registering them ad hoc invites two failure modes: a tool silently shadowing another because two modules picked the same name, and a tool that exists in code but never actually gets registered. We wanted the tool surface to be assembled from independent modules with those failure modes caught at import time, not at runtime.

## Decision

Each domain module owns a module-level `TOOLS` list, where every entry is a dict with `fn`, `name`, and `category`. The registry in `mcp_tools/__init__.py` imports each module's `TOOLS` and aggregates them through `_build_registry`, which walks every list, tracks seen names in a set, and raises `ValueError` on the first duplicate. The result is the `ALL_TOOLS` registry, plus helpers (`get_tool_functions`, `list_tools_by_category`, `get_tool_by_name`, `get_categories`) that the server and tests consume.

Adding a domain is two steps: create a module with a `TOOLS` list, and add one import line to the registry. Names are unique by construction because the build fails loudly if they are not.

## Consequences

- Many small, cohesive tool modules instead of one large file, organized by domain.
- Duplicate tool names are a hard import-time error, not a confusing runtime shadow.
- The registry is the single source of truth for what tools exist, which is what makes uniform wrapping at registration possible (see [ADR-0002](0002-auth-and-metrics-wrapping-at-registration.md)).
- `category` on every entry gives free grouping for discovery and per-category listing.
- A tool only counts if it is in a module's `TOOLS` list and that module is imported by the registry. Decorated functions that are never added to a `TOOLS` list are not registered, which keeps the registered count honest.
