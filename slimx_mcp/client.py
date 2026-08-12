"""The bounded MCP JSON-RPC client — the one place SlimX-MCP touches the network.

Transport semantics are byte-compatible with the in-process client this package was
extracted from (ControlRoom's ``services/mcp_runtime``): the same SSRF guard (resolved-IP
check, IPv4-mapped-IPv6 unwrapping, redirect re-validation), the same 5 MB default
response cap, the same SSE ``data:`` unwrapping, and the same JSON-RPC ``error``
unwrapping. Failures raise :class:`McpTransportError` with a stable ``category`` (and the
host maps categories back onto its own error surface), with detail strings kept identical
to the host's so delegated and in-process modes are indistinguishable to users.
"""

from __future__ import annotations

import base64
import ipaddress
import json
import logging
import socket
from collections.abc import Iterable
from typing import Any
from urllib import parse as urllib_parse
from urllib import request as urllib_request
from urllib.error import HTTPError, URLError

logger = logging.getLogger(__name__)

ALLOWED_URL_SCHEMES = {"http", "https"}
DEFAULT_MAX_RESPONSE_BYTES = 5 * 1024 * 1024
DEFAULT_TIMEOUT_SECONDS = 20.0

# Current stateless Streamable HTTP request profile. Every request is independent: there is no
# initialize/session manager in this transport revision. The body metadata and mirrored headers
# are deliberately prepared in this one module so package mode and service mode cannot drift.
MCP_PROTOCOL_VERSION = "2026-07-28"
MCP_PROTOCOL_VERSION_META_KEY = "io.modelcontextprotocol/protocolVersion"
MCP_CLIENT_INFO_META_KEY = "io.modelcontextprotocol/clientInfo"
MCP_CLIENT_CAPABILITIES_META_KEY = "io.modelcontextprotocol/clientCapabilities"
DEFAULT_CLIENT_INFO = {"name": "slimx-mcp", "version": "0.1.1"}
DEFAULT_CLIENT_CAPABILITIES: dict[str, Any] = {}

_NAMED_REQUEST_FIELDS = {
    "tools/call": "name",
    "resources/read": "uri",
    "prompts/get": "name",
}

# Only these caller-supplied header names are forwarded to the remote MCP server. The
# transport owns Content-Type/Accept itself; auth headers are resolved by the host (which
# owns tokens/secrets) and passed through. Anything else is dropped — a deliberate
# hardening default; widen it consciously if a connector ever needs a custom header.
FORWARDABLE_HEADER_NAMES = frozenset({"authorization", "x-api-key"})

# Error categories a host can rely on (stable contract; additive only).
CATEGORY_INVALID_URL = "invalid_url"
CATEGORY_INVALID_REQUEST = "invalid_request"
CATEGORY_BLOCKED_HOST = "blocked_host"
CATEGORY_REMOTE_HTTP = "remote_http"
CATEGORY_UNAVAILABLE = "unavailable"
CATEGORY_TIMEOUT = "timeout"
CATEGORY_OVERSIZE = "oversize"
CATEGORY_UNREADABLE = "unreadable"
CATEGORY_MCP_ERROR = "mcp_error"


class McpTransportError(Exception):
    """A bounded-transport failure with a stable category for host-side error mapping."""

    def __init__(self, category: str, detail: str, remote_status: int | None = None) -> None:
        super().__init__(detail)
        self.category = category
        self.detail = detail
        self.remote_status = remote_status


def validate_server_url(url: str) -> str:
    normalized = str(url or "").strip()
    if not normalized:
        raise McpTransportError(CATEGORY_INVALID_URL, "Remote MCP connector is missing serverUrl.")
    parsed = urllib_parse.urlparse(normalized)
    if parsed.scheme.lower() not in ALLOWED_URL_SCHEMES:
        raise McpTransportError(
            CATEGORY_INVALID_URL, "Remote MCP connector serverUrl must use http or https."
        )
    if not parsed.netloc:
        raise McpTransportError(
            CATEGORY_INVALID_URL, "Remote MCP connector serverUrl must include a host."
        )
    return normalized


def _resolve_ips(host: str) -> list[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    """Resolve a host to every A/AAAA address; an IP literal passes straight through."""
    try:
        return [ipaddress.ip_address(host)]
    except ValueError:
        pass
    infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    return [ipaddress.ip_address(info[4][0]) for info in infos]


def _ip_is_disallowed(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    # Map IPv4-in-IPv6 (::ffff:127.0.0.1) to its IPv4 form so a loopback/private address
    # cannot be smuggled through an IPv6 literal.
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return (
        ip.is_loopback
        or ip.is_link_local  # 169.254.0.0/16 — includes the 169.254.169.254 cloud metadata IP
        or ip.is_private  # RFC1918 + IPv6 unique-local, etc.
        or ip.is_reserved
        or ip.is_multicast
        or ip.is_unspecified
    )


def _assert_url_allowed(
    url: str, *, block_private_hosts: bool, allowed_internal_hosts: frozenset[str]
) -> None:
    """Reject a URL whose host resolves to a non-public address (SSRF guard).

    The host is resolved and rejected if *any* resolved IP is loopback/link-local/private/
    reserved/multicast/unspecified. Runs at request time and again on every redirect so the
    live DNS result is checked, not just the config-time string. Hosts on the explicit
    internal allowlist (operator-opted-in internal services, e.g. a bundled web-search MCP
    wrapper) are exempt by exact name. A host that does not resolve is left to fail in the
    normal transport path — there is nothing reachable to protect against.

    Residual: a DNS-rebinding TOCTOU remains (the address can change between this lookup
    and the socket connect); fully closing it requires pinning the connection to the
    validated IP, which is out of scope for this guard.
    """
    if not block_private_hosts:
        return
    host = urllib_parse.urlparse(url).hostname
    if not host:
        return
    if host.lower() in allowed_internal_hosts:
        return
    try:
        ips = _resolve_ips(host)
    except (OSError, UnicodeError):
        return  # unresolvable → the request will fail at connect time; no SSRF reach
    if any(_ip_is_disallowed(ip) for ip in ips):
        raise McpTransportError(
            CATEGORY_BLOCKED_HOST,
            "Remote MCP connector serverUrl resolves to a disallowed private, loopback, "
            "or link-local address. Set MCP_BLOCK_PRIVATE_HOSTS=false to allow a local "
            "MCP server.",
        )


class _ValidatingRedirectHandler(urllib_request.HTTPRedirectHandler):
    """Re-check each redirect target so a permitted host cannot 30x onto an internal address."""

    def __init__(self, *, block_private_hosts: bool, allowed_internal_hosts: frozenset[str]):
        super().__init__()
        self._block_private_hosts = block_private_hosts
        self._allowed_internal_hosts = allowed_internal_hosts

    def redirect_request(
        self,
        req: urllib_request.Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> urllib_request.Request | None:
        _assert_url_allowed(
            newurl,
            block_private_hosts=self._block_private_hosts,
            allowed_internal_hosts=self._allowed_internal_hosts,
        )
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _forwardable_headers(headers: dict[str, str] | None) -> dict[str, str]:
    forwarded = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
    }
    for name, value in (headers or {}).items():
        if name.lower() in FORWARDABLE_HEADER_NAMES and isinstance(value, str) and value:
            forwarded[name] = value
    return forwarded


def _request_params(params: dict[str, Any] | None) -> dict[str, Any]:
    """Return a non-mutating copy with the current per-request MCP identity metadata.

    A trusted host may supply its own client identity/capabilities in ``params._meta`` (service
    mode uses this so the remote sees ControlRoom as the client, not the transport proxy). Missing
    or malformed reserved values fall back to SlimX-MCP's identity. The protocol version is always
    forced to this transport's supported revision, so headers and body cannot disagree.
    """
    prepared = dict(params or {})
    raw_meta = prepared.get("_meta")
    meta = dict(raw_meta) if isinstance(raw_meta, dict) else {}
    client_info = meta.get(MCP_CLIENT_INFO_META_KEY)
    if not (
        isinstance(client_info, dict)
        and isinstance(client_info.get("name"), str)
        and client_info["name"].strip()
        and isinstance(client_info.get("version"), str)
        and client_info["version"].strip()
    ):
        client_info = dict(DEFAULT_CLIENT_INFO)
    client_capabilities = meta.get(MCP_CLIENT_CAPABILITIES_META_KEY)
    if not isinstance(client_capabilities, dict):
        client_capabilities = dict(DEFAULT_CLIENT_CAPABILITIES)
    meta[MCP_PROTOCOL_VERSION_META_KEY] = MCP_PROTOCOL_VERSION
    meta[MCP_CLIENT_INFO_META_KEY] = client_info
    meta[MCP_CLIENT_CAPABILITIES_META_KEY] = client_capabilities
    prepared["_meta"] = meta
    return prepared


def _encode_header_value(value: str) -> str:
    """Encode an MCP mirrored value using the 2026 base64 sentinel rule when needed."""
    sentinel = value.startswith("=?base64?") and value.endswith("?=")
    plain_ascii = (
        value == value.strip(" \t")
        and not sentinel
        and all(character == "\t" or 0x20 <= ord(character) <= 0x7E for character in value)
    )
    if plain_ascii:
        return value
    encoded = base64.b64encode(value.encode("utf-8")).decode("ascii")
    return f"=?base64?{encoded}?="


def _request_headers(
    headers: dict[str, str] | None, method: str, params: dict[str, Any]
) -> dict[str, str]:
    """Build required stateless headers from the same method/params sent in the body."""
    prepared = _forwardable_headers(headers)
    prepared["MCP-Protocol-Version"] = MCP_PROTOCOL_VERSION
    prepared["Mcp-Method"] = method
    named_field = _NAMED_REQUEST_FIELDS.get(method)
    if named_field is not None:
        value = params.get(named_field)
        if not isinstance(value, str) or not value:
            raise McpTransportError(
                CATEGORY_INVALID_REQUEST,
                f"MCP {method} request requires a non-empty params.{named_field} value.",
            )
        prepared["Mcp-Name"] = _encode_header_value(value)
    return prepared


def json_rpc(
    url: str,
    method: str,
    params: dict[str, Any] | None = None,
    *,
    headers: dict[str, str] | None = None,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
    max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES,
    block_private_hosts: bool = True,
    allowed_internal_hosts: Iterable[str] = (),
) -> dict[str, Any]:
    """Execute one bounded JSON-RPC 2.0 call against a remote MCP server.

    Returns the unwrapped ``result`` object (non-dict results come back as
    ``{"content": <value>}``). Every failure raises :class:`McpTransportError`.
    """
    validated_url = validate_server_url(url)
    allowlist = frozenset(host.strip().lower() for host in allowed_internal_hosts if host.strip())
    _assert_url_allowed(
        validated_url,
        block_private_hosts=block_private_hosts,
        allowed_internal_hosts=allowlist,
    )
    request_params = _request_params(params)
    payload = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": f"slimx-mcp-{method}",
            "method": method,
            "params": request_params,
        }
    ).encode("utf-8")
    request = urllib_request.Request(
        validated_url,
        data=payload,
        method="POST",
        headers=_request_headers(headers, method, request_params),
    )
    opener = urllib_request.build_opener(
        _ValidatingRedirectHandler(
            block_private_hosts=block_private_hosts, allowed_internal_hosts=allowlist
        )
    )
    try:
        with opener.open(request, timeout=timeout) as response:  # nosec B310 - host validated; redirects re-checked.
            raw_bytes = response.read(max_response_bytes + 1)
            if len(raw_bytes) > max_response_bytes:
                raise McpTransportError(
                    CATEGORY_OVERSIZE,
                    "MCP server response exceeded the "
                    f"{max_response_bytes / (1024 * 1024):g} MB transport limit.",
                )
            raw = raw_bytes.decode("utf-8")
    except HTTPError as exc:
        logger.warning("MCP %s failed with remote HTTP %s", method, exc.code)
        raise McpTransportError(
            CATEGORY_REMOTE_HTTP,
            f"MCP server returned HTTP {exc.code}: {exc.reason}",
            remote_status=exc.code,
        ) from exc
    except URLError as exc:
        logger.warning("MCP %s failed: server unavailable (%s)", method, exc.reason)
        raise McpTransportError(CATEGORY_UNAVAILABLE, "MCP server is unavailable.") from exc
    except TimeoutError as exc:
        logger.warning("MCP %s timed out after %ss", method, timeout)
        raise McpTransportError(CATEGORY_TIMEOUT, "MCP request timed out.") from exc

    # Streamable-HTTP servers answer JSON-RPC over SSE frames; take the last data payload.
    if raw.lstrip().startswith("data:") or raw.lstrip().startswith("event:"):
        data_lines = [
            line[5:].strip()
            for line in raw.splitlines()
            if line.startswith("data:") and line[5:].strip() not in {"[DONE]", ""}
        ]
        raw = data_lines[-1] if data_lines else "{}"
    try:
        decoded = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise McpTransportError(
            CATEGORY_UNREADABLE, "MCP server returned an unreadable response."
        ) from exc
    if isinstance(decoded, dict) and decoded.get("error"):
        error = decoded["error"]
        message = error.get("message") if isinstance(error, dict) else str(error)
        raise McpTransportError(CATEGORY_MCP_ERROR, f"MCP error: {message}")
    result = decoded.get("result") if isinstance(decoded, dict) else decoded
    return result if isinstance(result, dict) else {"content": result}
