"""Read-only HTTP API server for CONTROL TOWER CT-03."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from control_tower.fixtures import build_dashboard
from control_tower.logging import tower_logger
from control_tower.schema import CURRENT_SCHEMA_VERSION
from control_tower.security import (
    ALLOWED_LOOPBACK_HOSTS,
    sanitize_error,
    validate_host_header,
)

ALLOWED_ORIGINS = frozenset({"http://localhost:3000", "http://127.0.0.1:3000"})
LOOPBACK_HOST = "127.0.0.1"


class DashboardHandler(BaseHTTPRequestHandler):
    """Secure, loopback-only, read-only HTTP handler."""

    server_version = "ControlTowerBackend/3.0"

    def _write_json(
        self,
        status_code: int,
        payload: dict[str, Any],
        request_id: str | None = None,
    ) -> None:
        origin = self.headers.get("Origin")
        body = json.dumps(payload).encode("utf-8")

        self.send_response(status_code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store, max-age=0")
        self.send_header("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
        self.send_header("X-Content-Type-Options", "nosniff")

        if origin and origin in ALLOWED_ORIGINS:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Access-Control-Allow-Methods", "GET, HEAD, OPTIONS")
            self.send_header("Access-Control-Allow-Headers", "Content-Type")

        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self) -> None:
        origin = self.headers.get("Origin")
        if origin and origin in ALLOWED_ORIGINS:
            self.send_response(204)
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Access-Control-Allow-Methods", "GET, HEAD, OPTIONS")
            self.send_header("Access-Control-Allow-Headers", "Content-Type")
            self.send_header("Access-Control-Max-Age", "600")
            self.end_headers()
        else:
            self.send_response(403)
            self.end_headers()

    def do_GET(self) -> None:
        host = self.headers.get("Host")
        server_port = self.server.server_port if hasattr(self.server, "server_port") else None

        if not validate_host_header(host, server_port):
            tower_logger.log(
                component="HTTP",
                result_class="INVALID_HOST_HEADER",
                error_code="INVALID_HOST_HEADER",
                error_detail=f"Host header rejected: {sanitize_error(host)}",
            )
            self._write_json(400, {"error": "INVALID_HOST_HEADER"})
            return

        if self.path in ("/health", "/api/v1/health", "/api/v1/liveness"):
            self._write_json(
                200,
                {
                    "status": "HEALTHY",
                    "liveness": "PASS",
                    "service": "CONTROL_TOWER",
                    "schema_version": CURRENT_SCHEMA_VERSION,
                },
            )
            return

        if self.path in ("/ready", "/api/v1/ready", "/api/v1/readiness"):
            try:
                now = datetime.now(timezone.utc)
                root_dir = getattr(self.server, "root_dir", None)
                build_dashboard(now, root_dir=root_dir)
                self._write_json(
                    200,
                    {
                        "status": "READY",
                        "readiness": "PASS",
                        "service": "CONTROL_TOWER",
                        "schema_version": CURRENT_SCHEMA_VERSION,
                    },
                )
            except Exception as e:
                tower_logger.log(
                    component="READINESS",
                    result_class="NOT_READY",
                    error_code=type(e).__name__,
                    error_detail=sanitize_error(e),
                )
                self._write_json(
                    503,
                    {
                        "status": "NOT_READY",
                        "readiness": "FAIL",
                        "service": "CONTROL_TOWER",
                        "error": type(e).__name__,
                        "detail": sanitize_error(e),
                    },
                )
            return

        if self.path == "/api/v1/dashboard":
            try:
                now = datetime.now(timezone.utc)
                root_dir = getattr(self.server, "root_dir", None)
                data = build_dashboard(now, root_dir=root_dir)
                self._write_json(200, data)
            except Exception as e:
                tower_logger.log(
                    component="API",
                    result_class="SERVER_ERROR",
                    error_code=type(e).__name__,
                    error_detail=sanitize_error(e),
                )
                self._write_json(500, {"error": "INTERNAL_SERVER_ERROR", "detail": sanitize_error(e)})
            return

        self._write_json(404, {"error": "NOT_FOUND"})

    def do_HEAD(self) -> None:
        self.do_GET()

    def do_POST(self) -> None:
        self._write_json(405, {"error": "READ_ONLY: Mutations not permitted"})

    def do_PUT(self) -> None:
        self.do_POST()

    def do_PATCH(self) -> None:
        self.do_POST()

    def do_DELETE(self) -> None:
        self.do_POST()

    def log_message(self, format: str, *args: Any) -> None:
        pass


def create_server(
    port: int = 8000,
    host: str = LOOPBACK_HOST,
    root_dir: Path | None = None,
) -> ThreadingHTTPServer:
    """Create loopback backend HTTP server."""
    if host != LOOPBACK_HOST:
        raise ValueError(f"Non-loopback binding forbidden for security: host={host!r}")
    server = ThreadingHTTPServer((host, port), DashboardHandler)
    server.root_dir = root_dir
    return server
