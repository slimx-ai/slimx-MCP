"""SlimX-MCP service mode: the bounded transport behind an internal HTTP surface.

Runs as its own container on the compose-internal network (no host-published port). The
host application (ControlRoom) resolves connector auth headers — it owns tokens and the
OAuth lifecycle — and POSTs the prepared call to ``/rpc``; this service enforces the
transport bounds (SSRF guard, size cap, timeout clamp) and returns a **200 envelope**:
``{"ok": true, "result": …}`` or ``{"ok": false, "error": {category, detail,
remote_status}}``. Transport failures are data, not HTTP errors, so a service-level 401
(bad internal token) can never be confused with a remote MCP failure.

Env:
- ``SLIMX_MCP_INTERNAL_TOKEN`` — shared bearer token; enforced with a constant-time
  compare when set, empty = auth off (local-first). ``/health`` reports ``auth_enabled``
  so the host's deep health can flag a one-sided token (the SLIMX-RAG lesson).
- ``MCP_BLOCK_PRIVATE_HOSTS`` (default true) / ``MCP_ALLOWED_INTERNAL_HOSTS`` (csv) —
  the SSRF guard knobs, same names/semantics as the host's in-process client.
- ``MCP_MAX_RESPONSE_BYTES`` (default 5 MB), ``MCP_MAX_TIMEOUT_SECONDS`` (default 120) —
  hard caps a caller's request cannot exceed.
"""

from __future__ import annotations

import os
import secrets
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

from slimx_mcp import __version__
from slimx_mcp.client import (
    DEFAULT_MAX_RESPONSE_BYTES,
    DEFAULT_TIMEOUT_SECONDS,
    McpTransportError,
    json_rpc,
)

app = FastAPI(title="SlimX-MCP", version=__version__)


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _env_float(name: str, default: float) -> float:
    raw = os.environ.get(name)
    try:
        return float(raw) if raw is not None and raw.strip() else default
    except ValueError:
        return default


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    try:
        return int(raw) if raw is not None and raw.strip() else default
    except ValueError:
        return default


def _allowed_internal_hosts() -> list[str]:
    raw = os.environ.get("MCP_ALLOWED_INTERNAL_HOSTS", "")
    return [host.strip().lower() for host in raw.split(",") if host.strip()]


def require_internal_token(authorization: str | None = Header(default=None)) -> None:
    token = os.environ.get("SLIMX_MCP_INTERNAL_TOKEN", "").strip()
    if not token:
        return
    expected = f"Bearer {token}"
    if authorization is None or not secrets.compare_digest(authorization, expected):
        raise HTTPException(status_code=401, detail="Missing or invalid internal service token")


@app.get("/health")
def health() -> dict[str, Any]:
    return {
        "status": "ok",
        "service": "slimx-mcp",
        "version": __version__,
        "auth_enabled": bool(os.environ.get("SLIMX_MCP_INTERNAL_TOKEN", "").strip()),
    }


class RpcRequest(BaseModel):
    """One prepared MCP JSON-RPC call. ``headers`` arrive already resolved by the host
    (only allowlisted auth header names are forwarded; see ``FORWARDABLE_HEADER_NAMES``)."""

    url: str
    method: str
    params: dict[str, Any] = Field(default_factory=dict)
    headers: dict[str, str] = Field(default_factory=dict)
    timeout: float | None = Field(default=None, gt=0)


@app.post("/rpc")
def rpc(body: RpcRequest, _: None = Depends(require_internal_token)) -> dict[str, Any]:
    max_timeout = _env_float("MCP_MAX_TIMEOUT_SECONDS", 120.0)
    timeout = min(body.timeout or DEFAULT_TIMEOUT_SECONDS, max_timeout)
    try:
        result = json_rpc(
            body.url,
            body.method,
            body.params,
            headers=body.headers,
            timeout=timeout,
            max_response_bytes=_env_int("MCP_MAX_RESPONSE_BYTES", DEFAULT_MAX_RESPONSE_BYTES),
            block_private_hosts=_env_bool("MCP_BLOCK_PRIVATE_HOSTS", True),
            allowed_internal_hosts=_allowed_internal_hosts(),
        )
    except McpTransportError as exc:
        return {
            "ok": False,
            "error": {
                "category": exc.category,
                "detail": exc.detail,
                "remote_status": exc.remote_status,
            },
        }
    return {"ok": True, "result": result}
