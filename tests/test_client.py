from __future__ import annotations

import pytest

from slimx_mcp.client import (
    MCP_CLIENT_CAPABILITIES_META_KEY,
    MCP_CLIENT_INFO_META_KEY,
    MCP_PROTOCOL_VERSION,
    MCP_PROTOCOL_VERSION_META_KEY,
    McpTransportError,
    json_rpc,
    validate_server_url,
)


def _call(base: str, path: str = "/ok", method: str = "tools/list", **kwargs):
    kwargs.setdefault("block_private_hosts", False)
    return json_rpc(f"{base}{path}", method, **kwargs)


# --- URL validation -----------------------------------------------------------------


@pytest.mark.parametrize(
    ("url", "fragment"),
    [
        ("", "missing serverUrl"),
        ("ftp://example.com/mcp", "must use http or https"),
        ("http://", "must include a host"),
    ],
)
def test_validate_server_url_rejects_bad_urls(url, fragment):
    with pytest.raises(McpTransportError) as excinfo:
        validate_server_url(url)
    assert excinfo.value.category == "invalid_url"
    assert fragment in excinfo.value.detail


# --- SSRF guard ---------------------------------------------------------------------


def test_private_host_is_blocked_by_default(fake_mcp_server):
    with pytest.raises(McpTransportError) as excinfo:
        json_rpc(f"{fake_mcp_server}/ok", "tools/list")
    assert excinfo.value.category == "blocked_host"


def test_internal_allowlist_exempts_host_by_exact_name(fake_mcp_server):
    result = json_rpc(
        f"{fake_mcp_server}/ok",
        "tools/list",
        allowed_internal_hosts=["127.0.0.1"],
    )
    assert result["tools"][0]["name"] == "search"


def test_guard_can_be_disabled_for_local_dev(fake_mcp_server):
    result = _call(fake_mcp_server)
    assert [tool["name"] for tool in result["tools"]] == ["search", "read_file"]


def test_redirect_to_non_allowlisted_loopback_host_is_blocked(fake_mcp_server):
    # First hop is allowlisted (127.0.0.1); the 302 target host (localhost) is not, and
    # resolves to loopback — the redirect re-validation must reject it.
    with pytest.raises(McpTransportError) as excinfo:
        json_rpc(
            f"{fake_mcp_server}/redirect-loopback",
            "tools/list",
            allowed_internal_hosts=["127.0.0.1"],
        )
    assert excinfo.value.category == "blocked_host"


# --- response handling ----------------------------------------------------------------


def test_non_dict_result_wraps_as_content(fake_mcp_server):
    assert _call(fake_mcp_server, path="/scalar") == {"content": [1, 2, 3]}


def test_sse_framed_response_is_unwrapped(fake_mcp_server):
    assert _call(fake_mcp_server, path="/sse") == {"tools": []}


def test_only_auth_and_required_protocol_headers_are_forwarded(fake_mcp_server):
    result = _call(
        fake_mcp_server,
        path="/echo-headers",
        headers={
            "Authorization": "Bearer connector-token",
            "x-api-key": "key-123",
            "X-Sneaky": "nope",
            "Content-Type": "text/evil",
        },
    )
    received = {name.lower(): value for name, value in result["headers"].items()}
    assert received["authorization"] == "Bearer connector-token"
    assert received["x-api-key"] == "key-123"
    assert received["content-type"] == "application/json"
    assert received["mcp-protocol-version"] == MCP_PROTOCOL_VERSION
    assert received["mcp-method"] == "tools/list"
    assert "mcp-name" not in received
    assert "x-sneaky" not in received


def test_current_stateless_envelope_is_added_without_mutating_caller_params(fake_mcp_server):
    params = {
        "name": "search",
        "arguments": {"query": "slimx"},
        "_meta": {"trace-id": "trace-1"},
    }

    result = _call(
        fake_mcp_server,
        path="/echo-headers",
        method="tools/call",
        params=params,
    )

    received = {name.lower(): value for name, value in result["headers"].items()}
    request = result["request"]
    meta = request["params"]["_meta"]
    assert received["mcp-protocol-version"] == MCP_PROTOCOL_VERSION
    assert received["mcp-method"] == request["method"] == "tools/call"
    assert received["mcp-name"] == request["params"]["name"] == "search"
    assert meta[MCP_PROTOCOL_VERSION_META_KEY] == MCP_PROTOCOL_VERSION
    assert meta[MCP_CLIENT_INFO_META_KEY] == {"name": "slimx-mcp", "version": "0.1.1"}
    assert meta[MCP_CLIENT_CAPABILITIES_META_KEY] == {}
    assert meta["trace-id"] == "trace-1"
    assert params["_meta"] == {"trace-id": "trace-1"}


def test_named_request_header_uses_base64_sentinel_for_non_ascii_uri(fake_mcp_server):
    result = _call(
        fake_mcp_server,
        path="/echo-headers",
        method="resources/read",
        params={"uri": "file:///projects/مرحبا.md"},
    )

    received = {name.lower(): value for name, value in result["headers"].items()}
    assert received["mcp-name"].startswith("=?base64?")
    assert received["mcp-name"].endswith("?=")


def test_named_request_without_name_fails_before_network(fake_mcp_server):
    with pytest.raises(McpTransportError) as excinfo:
        _call(fake_mcp_server, method="tools/call", params={"arguments": {}})
    assert excinfo.value.category == "invalid_request"


def test_explicit_legacy_tolerant_fixture_still_accepts_additive_envelope(fake_mcp_server):
    """The named /ok fixture ignores unknown headers/_meta like older bundled servers do."""
    result = _call(fake_mcp_server, path="/ok", method="tools/list")
    assert [tool["name"] for tool in result["tools"]] == ["search", "read_file"]


# --- failure categories -----------------------------------------------------------------


def test_jsonrpc_error_surfaces_as_mcp_error(fake_mcp_server):
    with pytest.raises(McpTransportError) as excinfo:
        _call(fake_mcp_server, path="/rpc-error")
    assert excinfo.value.category == "mcp_error"
    assert excinfo.value.detail == "MCP error: boom"


def test_remote_http_failure_carries_status(fake_mcp_server):
    with pytest.raises(McpTransportError) as excinfo:
        _call(fake_mcp_server, path="/http500")
    assert excinfo.value.category == "remote_http"
    assert excinfo.value.remote_status == 500
    assert "HTTP 500" in excinfo.value.detail


def test_unreachable_server_is_unavailable():
    with pytest.raises(McpTransportError) as excinfo:
        json_rpc("http://127.0.0.1:9/ok", "tools/list", block_private_hosts=False)
    assert excinfo.value.category == "unavailable"
    assert excinfo.value.detail == "MCP server is unavailable."


def test_oversized_response_is_rejected(fake_mcp_server):
    with pytest.raises(McpTransportError) as excinfo:
        _call(fake_mcp_server, path="/big", max_response_bytes=1024)
    assert excinfo.value.category == "oversize"


def test_non_json_response_is_unreadable(fake_mcp_server):
    with pytest.raises(McpTransportError) as excinfo:
        _call(fake_mcp_server, path="/not-json")
    assert excinfo.value.category == "unreadable"


def test_slow_server_times_out(fake_mcp_server):
    with pytest.raises(McpTransportError) as excinfo:
        _call(fake_mcp_server, path="/slow", timeout=0.2)
    assert excinfo.value.category == "timeout"
    assert excinfo.value.detail == "MCP request timed out."
