"""Dependency-free, loopback-only, read-only CONTROL TOWER HTTP API."""

from __future__ import annotations

import argparse
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

from control_tower.fixtures import build_dashboard

LOOPBACK_HOST = "127.0.0.1"
DEFAULT_PORT = 8000
ALLOWED_ORIGINS = frozenset(
    {"http://localhost:3000", "http://127.0.0.1:3000"}
)


class DashboardHandler(BaseHTTPRequestHandler):
    """Serve two GET endpoints and reject every mutation without reading a body."""

    server_version = "ControlTower/0.2"

    def _write_json(self, status: int, payload: dict[str, object]) -> None:
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        origin = self.headers.get("Origin")
        if origin in ALLOWED_ORIGINS:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Vary", "Origin")
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", "default-src 'none'")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        path = urlsplit(self.path).path
        if path == "/api/v1/dashboard":
            self._write_json(200, build_dashboard())
            return
        if path == "/health":
            self._write_json(
                200,
                {
                    "status": "HEALTHY",
                    "scope": "CONTROL_TOWER_APPLICATION",
                    "read_only": True,
                    "upstream_systems_included": False,
                },
            )
            return
        self._write_json(404, {"error": "NOT_FOUND"})

    def _read_only(self) -> None:
        self._write_json(405, {"error": "READ_ONLY_PHASE_0"})

    do_POST = _read_only
    do_PUT = _read_only
    do_PATCH = _read_only
    do_DELETE = _read_only

    def log_message(self, message: str, *args: object) -> None:
        print(f"CONTROL_TOWER_API {self.address_string()} {message % args}")


def create_server(port: int = DEFAULT_PORT) -> ThreadingHTTPServer:
    """Create a server that cannot be configured to listen beyond loopback."""
    return ThreadingHTTPServer((LOOPBACK_HOST, port), DashboardHandler)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    args = parser.parse_args()
    server = create_server(args.port)
    print(f"CONTROL TOWER API: http://{LOOPBACK_HOST}:{args.port}")
    server.serve_forever()


if __name__ == "__main__":
    main()
