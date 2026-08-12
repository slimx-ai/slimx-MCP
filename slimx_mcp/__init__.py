"""SlimX-MCP: the bounded MCP transport layer of the SlimX platform.

Extracted from SlimX-AI ControlRoom (extraction Stage 3). This package owns exactly one
job: executing MCP JSON-RPC calls against remote MCP servers **safely** — URL validation,
SSRF host guarding (with redirect re-validation), response size caps, timeouts, SSE
unwrapping, and JSON-RPC error unwrapping. It deliberately does NOT own connector
registries, OAuth token lifecycles, tool whitelisting policy, or UI — those stay with the
host application (ControlRoom), which resolves auth headers and passes them in.

Two consumption modes:
- **Package mode**: ``from slimx_mcp import json_rpc`` — the bounded client, in-process.
- **Service mode**: run ``slimx_mcp.service:app`` (see the Dockerfile) and POST to
  ``/rpc``; the host talks to it over an internal network with a shared token
  (``SLIMX_MCP_INTERNAL_TOKEN``, one value on both sides).
"""

from slimx_mcp.client import (
    DEFAULT_MAX_RESPONSE_BYTES as DEFAULT_MAX_RESPONSE_BYTES,
    MCP_PROTOCOL_VERSION as MCP_PROTOCOL_VERSION,
    McpTransportError as McpTransportError,
    json_rpc as json_rpc,
    validate_server_url as validate_server_url,
)

__version__ = "0.1.1"

__all__ = [
    "DEFAULT_MAX_RESPONSE_BYTES",
    "MCP_PROTOCOL_VERSION",
    "McpTransportError",
    "json_rpc",
    "validate_server_url",
    "__version__",
]
