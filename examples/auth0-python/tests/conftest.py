"""Shared fake gateway that mimics ssod for the tests."""

from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Iterator
import contextlib

JSON = "application/json"


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *_: object) -> None:  # silence test output
        pass

    def _send(self, status: int, body: str = "", location: str = "") -> None:
        self.send_response(status)
        self.send_header("Content-Type", JSON)
        if location:
            self.send_header("Location", location)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body.encode())

    def do_GET(self) -> None:  # noqa: N802 - http.server API
        path = self.path.split("?")[0]
        routes = {
            "/healthz": lambda: self._send(200, '{"status":"ok"}'),
            "/providers": lambda: self._send(200, '{"providers":["mock","auth0"]}'),
            "/auth/mock/login": lambda: self._send(302, location="/mock/authorize?state=s1&code_challenge=c&code_challenge_method=S256"),
            "/mock/authorize": lambda: self._send(302, location="/auth/mock/callback?code=mock-code&state=s1"),
            "/auth/mock/callback": lambda: self._send(
                200, '{"provider_id":"mock","user":{"id":"u1","email":"a@example.com","display_name":"Mock User"}}'
            ),
            "/auth/auth0/login": lambda: self._send(
                302, location="https://tenant.example.test/authorize?state=s2&code_challenge=c&code_challenge_method=S256"
            ),
            "/auth/missing/login": lambda: self._send(404, '{"code":"PROVIDER_NOT_FOUND","message":"missing"}'),
            "/auth/weak/login": lambda: self._send(302, location="https://tenant.example.test/authorize?state=s3"),
            "/auth/bad/callback": lambda: self._send(200, "not json"),
        }
        routes.get(path, lambda: self._send(500, "boom"))()


@contextlib.contextmanager
def fake_gateway() -> Iterator[str]:
    """Run the fake gateway on a random loopback port and yield its base URL."""
    server = HTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
