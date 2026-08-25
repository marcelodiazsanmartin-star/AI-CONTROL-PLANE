"""Dedicated read-only loopback static file server for CONTROL TOWER frontend UI."""

from __future__ import annotations

import mimetypes
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from control_tower.security import (
    ALLOWED_LOOPBACK_HOSTS,
    SecurityError,
    safe_resolve_path,
    sanitize_error,
    validate_host_header,
)

FRONTEND_ALLOWLIST = frozenset({"index.html", "app.js", "styles.css"})


class FrontendHandler(BaseHTTPRequestHandler):
    """Secure loopback handler for frontend assets."""

    server_version = "ControlTowerFrontend/3.0"

    def _get_frontend_dir(self) -> Path:
        root_dir = getattr(self.server, "root_dir", None)
        if root_dir:
            return (Path(root_dir) / "control_tower" / "frontend").resolve()
        return (Path(__file__).resolve().parent / "frontend").resolve()

    def _set_security_headers(self, content_type: str) -> None:
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Security-Policy", "default-src 'self'; connect-src http://127.0.0.1:8000; style-src 'self'; script-src 'self'; object-src 'none'; base-uri 'none'; form-action 'none'")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Cache-Control", "no-store, max-age=0")
        self.end_headers()

    def do_GET(self) -> None:
        host = self.headers.get("Host")
        server_port = self.server.server_port if hasattr(self.server, "server_port") else None
        if not validate_host_header(host, server_port):
            self.send_response(400)
            self._set_security_headers("text/plain; charset=utf-8")
            self.wfile.write(b"INVALID_HOST_HEADER\n")
            return

        raw_path = self.path.split("?")[0].strip("/")
        if not raw_path:
            raw_path = "index.html"

        if raw_path not in FRONTEND_ALLOWLIST:
            self.send_response(404)
            self._set_security_headers("text/plain; charset=utf-8")
            self.wfile.write(b"NOT_FOUND\n")
            return

        frontend_dir = self._get_frontend_dir()
        try:
            target_file = safe_resolve_path(frontend_dir / raw_path, frontend_dir, FRONTEND_ALLOWLIST)
        except SecurityError:
            self.send_response(403)
            self._set_security_headers("text/plain; charset=utf-8")
            self.wfile.write(b"FORBIDDEN\n")
            return

        if not target_file.exists() or not target_file.is_file():
            self.send_response(404)
            self._set_security_headers("text/plain; charset=utf-8")
            self.wfile.write(b"NOT_FOUND\n")
            return

        content_type, _ = mimetypes.guess_type(str(target_file))
        if not content_type:
            content_type = "application/octet-stream"
        if "html" in content_type or "javascript" in content_type or "css" in content_type:
            content_type += "; charset=utf-8"

        content = target_file.read_bytes()
        self.send_response(200)
        self._set_security_headers(content_type)
        self.wfile.write(content)

    def do_HEAD(self) -> None:
        self.do_GET()

    def do_POST(self) -> None:
        self.send_response(405)
        self._set_security_headers("text/plain; charset=utf-8")
        self.wfile.write(b"READ_ONLY: Mutations not permitted\n")

    def do_PUT(self) -> None:
        self.do_POST()

    def do_DELETE(self) -> None:
        self.do_POST()

    def do_PATCH(self) -> None:
        self.do_POST()

    def log_message(self, format: str, *args: Any) -> None:
        pass


def create_frontend_server(
    port: int = 3000,
    host: str = "127.0.0.1",
    root_dir: Path | None = None,
) -> ThreadingHTTPServer:
    """Create loopback frontend HTTP server."""
    server = ThreadingHTTPServer((host, port), FrontendHandler)
    server.root_dir = root_dir
    return server
