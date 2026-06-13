# ADR-0002: Auth and metrics wrapping at registration

- Status: Accepted
- Date: 2026-06-12

## Context

Every tool needs the same two cross-cutting behaviors: metrics tracking so we can see call volume and latency, and auth enforcement so a caller cannot invoke a tool they lack permission for. The wrong way to do this is to sprinkle decorators across every tool definition, where it is easy to forget one and ship an unprotected tool. We wanted these behaviors applied uniformly to the whole tool surface in exactly one place, with no per-tool opt-in.

## Decision

Wrapping happens once, in the registration loop in `network_mcp_async.py`, over the `ALL_TOOLS` registry from [ADR-0001](0001-modular-tool-registry.md):

```python
for _entry in ALL_TOOLS:
    _tracked = track_tool_call(_entry["name"], _entry["fn"])
    _wrapped = auth_enforced(_entry["name"], _tracked)
    mcp.tool()(_wrapped)
```

Each tool is wrapped with metrics tracking, then with auth enforcement, then registered with the MCP server. The order is deliberate: auth is the outermost decision so denied calls are rejected before anything else runs.

`auth_enforced` (in `security/tool_wrapper.py`) resolves the tool's required permission and command policy from `tool_permissions.py` at registration time. When `MCP_AUTH_ENABLED` is false (local dev), it returns the original function unchanged, so there is zero per-call overhead when auth is off. Denials are logged through the event logger with the tool name and user.

## Consequences

- A new tool inherits metrics and auth automatically the moment it joins the registry. There is no per-tool decorator to forget.
- Enforcement and tracking are defined in one place, so the policy is auditable by reading a single loop.
- Auth is the outermost wrapper, so an unauthorized call never reaches the metrics-tracked function body.
- Because the registry is the only registration path, there is no back door that registers a tool while skipping the wrappers.
