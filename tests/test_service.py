from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from slimx_mcp import MCP_PROTOCOL_VERSION, __version__
from slimx_mcp.service import app


@pytest.fixture()
def client(monkeypatch):
    monkeypatch.delenv("SLIMX_MCP_INTERNAL_TOKEN", raising=False)
    monkeypatch.setenv("MCP_BLOCK_PRIVATE_HOSTS", "false")
    return TestClient(app)


def test_health_reports_identity_and_auth_state(client):
    body = client.get("/health").json()
    assert body == {
        "status": "ok",
        "service": "slimx-mcp",
        "version": __version__,
        "auth_enabled": False,
    }


def test_rpc_success_envelope(client, fake_mcp_server):
    response = client.post("/rpc", json={"url": f"{fake_mcp_server}/ok", "method": "tools/list"})
    assert response.status_code == 200
    body = response.json()
    assert body["ok"] is True
    assert [tool["name"] for tool in body["result"]["tools"]] == ["search", "read_file"]


def test_rpc_service_emits_current_stateless_envelope(client, fake_mcp_server):
    response = client.post(
        "/rpc",
        json={
            "url": f"{fake_mcp_server}/echo-headers",
            "method": "tools/call",
            "params": {
                "name": "search",
                "arguments": {"query": "slimx"},
                "_meta": {
                    "io.modelcontextprotocol/clientInfo": {
                        "name": "slimx-controlroom",
                        "version": "0.1.0",
                    },
                    "io.modelcontextprotocol/clientCapabilities": {"sampling": {}},
                },
            },
        },
    )

    assert response.status_code == 200
    result = response.json()["result"]
    headers = {name.lower(): value for name, value in result["headers"].items()}
    request = result["request"]
    assert headers["mcp-protocol-version"] == MCP_PROTOCOL_VERSION
    assert headers["mcp-method"] == "tools/call"
    assert headers["mcp-name"] == "search"
    assert request["params"]["_meta"] == {
        "io.modelcontextprotocol/clientInfo": {
            "name": "slimx-controlroom",
            "version": "0.1.0",
        },
        "io.modelcontextprotocol/clientCapabilities": {"sampling": {}},
        "io.modelcontextprotocol/protocolVersion": MCP_PROTOCOL_VERSION,
    }


def test_rpc_transport_failure_is_an_envelope_not_an_http_error(client):
    response = client.post("/rpc", json={"url": "http://127.0.0.1:9/ok", "method": "tools/list"})
    assert response.status_code == 200
    body = response.json()
    assert body["ok"] is False
    assert body["error"]["category"] == "unavailable"
    assert body["error"]["detail"] == "MCP server is unavailable."
    assert body["error"]["remote_status"] is None


def test_rpc_remote_http_error_carries_status(client, fake_mcp_server):
    body = client.post(
        "/rpc", json={"url": f"{fake_mcp_server}/http500", "method": "tools/list"}
    ).json()
    assert body["ok"] is False
    assert body["error"]["category"] == "remote_http"
    assert body["error"]["remote_status"] == 500


def test_rpc_enforces_ssrf_guard_from_env(client, fake_mcp_server, monkeypatch):
    monkeypatch.setenv("MCP_BLOCK_PRIVATE_HOSTS", "true")
    body = client.post("/rpc", json={"url": f"{fake_mcp_server}/ok", "method": "tools/list"}).json()
    assert body["ok"] is False
    assert body["error"]["category"] == "blocked_host"

    monkeypatch.setenv("MCP_ALLOWED_INTERNAL_HOSTS", "other-host, 127.0.0.1")
    body = client.post("/rpc", json={"url": f"{fake_mcp_server}/ok", "method": "tools/list"}).json()
    assert body["ok"] is True


def test_rpc_timeout_is_clamped_by_env_cap(client, fake_mcp_server, monkeypatch):
    monkeypatch.setenv("MCP_MAX_TIMEOUT_SECONDS", "0.2")
    body = client.post(
        "/rpc",
        json={"url": f"{fake_mcp_server}/slow", "method": "tools/list", "timeout": 3600},
    ).json()
    assert body["ok"] is False
    assert body["error"]["category"] == "timeout"


def test_internal_token_enforced_with_constant_time_compare(monkeypatch, fake_mcp_server):
    monkeypatch.setenv("SLIMX_MCP_INTERNAL_TOKEN", "s3cret")
    monkeypatch.setenv("MCP_BLOCK_PRIVATE_HOSTS", "false")
    client = TestClient(app)

    assert client.get("/health").json()["auth_enabled"] is True

    payload = {"url": f"{fake_mcp_server}/ok", "method": "tools/list"}
    assert client.post("/rpc", json=payload).status_code == 401
    assert (
        client.post("/rpc", json=payload, headers={"Authorization": "Bearer wrong"}).status_code
        == 401
    )
    ok = client.post("/rpc", json=payload, headers={"Authorization": "Bearer s3cret"})
    assert ok.status_code == 200
    assert ok.json()["ok"] is True
