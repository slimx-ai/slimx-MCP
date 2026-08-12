# SlimX-MCP

The bounded **MCP transport gateway** of the SlimX platform — the layer that actually
talks to remote [MCP](https://modelcontextprotocol.io) servers, extracted from
SlimX-AI ControlRoom.

SlimX layering:

| Layer | Repo | Job |
| --- | --- | --- |
| Model execution | `slimx` | providers, payloads, retries, parallel fan-out |
| Knowledge / retrieval | `SlimX-RAG` | ingest, chunk, embed, index, retrieve, cite |
| **Connector transport** | **`SlimX-MCP`** | **SSRF-guarded, size/time-capped MCP JSON-RPC** |
| Reasoning workspace | `slimx-brainstorm` (ControlRoom) | UI, registry, permissions, orchestration |

## What it owns — and deliberately does not

**Owns:** the MCP 2026-07-28 stateless Streamable HTTP request envelope, URL validation,
SSRF host guarding (resolved-IP checks, IPv4-mapped-IPv6
unwrapping, redirect re-validation), response size caps (5 MB default), timeout clamps,
SSE unwrapping of streamable-HTTP responses, JSON-RPC error unwrapping, and a stable
error-category contract (`invalid_url | invalid_request | blocked_host | remote_http | unavailable |
timeout | oversize | unreadable | mcp_error`).

**Does not own:** connector registries, OAuth token lifecycles, tool whitelisting policy,
approval models, or UI. The host application resolves auth headers (it owns the secrets)
and passes them in; only `Authorization` / `x-api-key` are forwarded to the remote.
Generic *write* tool invocation is not special-cased here — hosts must gate what they
call through their own policy (ControlRoom invokes read-only whitelisted tools only).

## Package mode

```python
from slimx_mcp import json_rpc, McpTransportError

result = json_rpc(
    "https://mcp.example.com/mcp",
    "tools/list",
    headers={"Authorization": "Bearer <token>"},
    timeout=20.0,
    allowed_internal_hosts=["web-search-mcp"],  # exact-name SSRF exemptions
)
```

Every call is one independent POST. SlimX-MCP adds `MCP-Protocol-Version`, `Mcp-Method`,
the required `Mcp-Name` for named calls, and matching protocol version/client
identity/capabilities under `params._meta`. It does not create protocol sessions or require a
universal `initialize` exchange. In service mode, a valid host-supplied client identity is
preserved so the remote sees the actual MCP host rather than the transport proxy.

## Service mode

```bash
docker build -t slimx-mcp .
docker run --rm -p 8091:8091 -e SLIMX_MCP_INTERNAL_TOKEN=... slimx-mcp
```

| Endpoint | Description |
| --- | --- |
| `GET /health` | `{status, service, version, auth_enabled}` |
| `POST /rpc` | body `{url, method, params?, headers?, timeout?}` → **200 envelope** `{"ok": true, "result": …}` or `{"ok": false, "error": {category, detail, remote_status}}` |

Transport failures are **data** (a 200 envelope), never HTTP errors — so a service-level
401 (bad internal token) can never be confused with a remote MCP failure.

### Environment

| Variable | Default | Meaning |
| --- | --- | --- |
| `SLIMX_MCP_INTERNAL_TOKEN` | *(empty = auth off)* | shared bearer token, constant-time compared; set the **same value on both sides** |
| `MCP_BLOCK_PRIVATE_HOSTS` | `true` | reject URLs resolving to private/loopback/link-local/reserved addresses |
| `MCP_ALLOWED_INTERNAL_HOSTS` | *(empty)* | comma-separated exact hostnames exempt from the guard (operator-opted-in internal services) |
| `MCP_MAX_RESPONSE_BYTES` | `5242880` | transport response cap |
| `MCP_MAX_TIMEOUT_SECONDS` | `120` | hard cap on a caller-requested timeout |

### With ControlRoom

ControlRoom keeps its in-process client by default. To route its MCP traffic through this
service instead (its `_json_rpc` chokepoint delegates; **no silent fallback** — if the
service is down, MCP operations fail loudly and `/health/deep` reports it):

```bash
# in slimx-brainstorm/.env
ENABLE_SLIMX_MCP_SERVICE=true
SLIMX_MCP_INTERNAL_TOKEN=<one value, both containers>
COMPOSE_PROFILES=mcp-service   # builds this repo from the sibling checkout ../SlimX-MCP
```

## Development

```bash
pip install -e '.[dev]'
ruff check .
pytest
```

Tests run against a real local HTTP server (the client is stdlib-`urllib` based), so they
also exercise the SSRF guard and its allowlist/off switches for real.

## License

MIT — see [LICENSE](LICENSE).
