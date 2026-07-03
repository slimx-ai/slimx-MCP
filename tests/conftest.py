"""A real local MCP-ish HTTP server for transport tests.

The client is stdlib-urllib based, so tests exercise it against an actual socket rather
than a mocked transport. Behavior is keyed by request path; ``/ok`` answers per JSON-RPC
method. Tests must opt out of the SSRF guard (``block_private_hosts=False`` or an
allowlist entry) to reach it — which is itself part of what the tests verify.
"""

from __future__ import annotations

import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest


class _FakeMcpHandler(BaseHTTPRequestHandler):
    def log_message(self, *args):  # keep test output clean
        pass

    def _send(self, status: int, body: bytes, content_type: str = "application/json") -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:  # noqa: N802 - stdlib handler API
        length = int(self.headers.get("Content-Length") or 0)
        request = json.loads(self.rfile.read(length) or b"{}")
        path = self.path
        if path == "/ok":
            method = request.get("method")
            if method == "tools/list":
                result = {"tools": [{"name": "search"}, {"name": "read_file"}]}
            elif method == "tools/call":
                result = {"content": [{"text": json.dumps({"echo": request.get("params")})}]}
            else:
                result = {"content": "plain"}
            self._send(200, json.dumps({"jsonrpc": "2.0", "result": result}).encode())
        elif path == "/echo-headers":
            headers = {name: value for name, value in self.headers.items()}
            self._send(
                200,
                json.dumps({"jsonrpc": "2.0", "result": {"headers": headers}}).encode(),
            )
        elif path == "/scalar":
            self._send(200, json.dumps({"jsonrpc": "2.0", "result": [1, 2, 3]}).encode())
        elif path == "/sse":
            body = (
                'event: message\ndata: {"jsonrpc": "2.0", "result": {"tools": []}}\n\n'
            ).encode()
            self._send(200, body, content_type="text/event-stream")
        elif path == "/rpc-error":
            self._send(
                200,
                json.dumps(
                    {"jsonrpc": "2.0", "error": {"code": -32000, "message": "boom"}}
                ).encode(),
            )
        elif path == "/http500":
            self._send(500, b"server exploded", content_type="text/plain")
        elif path == "/not-json":
            self._send(200, b"<html>definitely not json</html>", content_type="text/html")
        elif path == "/big":
            self._send(200, b"x" * 4096, content_type="application/json")
        elif path == "/slow":
            time.sleep(1.0)
            self._send(200, json.dumps({"jsonrpc": "2.0", "result": {}}).encode())
        elif path == "/redirect-loopback":
            self.send_response(302)
            self.send_header("Location", f"http://localhost:{self.server.server_port}/ok")
            self.send_header("Content-Length", "0")
            self.end_headers()
        else:
            self._send(404, b"{}")


@pytest.fixture(scope="session")
def fake_mcp_server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _FakeMcpHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_port}"
    server.shutdown()
