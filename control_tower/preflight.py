"""Deterministic preflight validation for CONTROL TOWER CT-03 service startup."""

from __future__ import annotations

import os
import socket
import sys
from pathlib import Path
from typing import Any

from control_tower.security import SecurityError, sanitize_error

REQUIRED_PYTHON_VERSION = (3, 12)
REQUIRED_FRONTEND_FILES = ("index.html", "app.js", "styles.css")
DEFAULT_BACKEND_PORT = 8000
DEFAULT_FRONTEND_PORT = 3000
LOOPBACK_IP = "127.0.0.1"


class PreflightError(SecurityError):
    """Raised when preflight checks fail before startup."""


def is_port_available(port: int, host: str = LOOPBACK_IP) -> bool:
    """Check if loopback port is available for binding."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 0)
        try:
            s.bind((host, port))
            return True
        except (OSError, socket.error):
            return False


def run_preflight(
    root_dir: Path | None = None,
    backend_port: int = DEFAULT_BACKEND_PORT,
    frontend_port: int = DEFAULT_FRONTEND_PORT,
    check_ports: bool = True,
) -> dict[str, Any]:
    """Execute all deterministic preflight checks and return verified configuration."""
    # 1. Python version check
    if sys.version_info < REQUIRED_PYTHON_VERSION:
        raise PreflightError(
            f"Python {REQUIRED_PYTHON_VERSION[0]}.{REQUIRED_PYTHON_VERSION[1]}+ required; "
            f"current runtime is {sys.version_info.major}.{sys.version_info.minor}"
        )

    # 2. Root directory resolution
    resolved_root = (root_dir or Path(__file__).resolve().parents[1]).resolve()
    if not resolved_root.exists() or not resolved_root.is_dir():
        raise PreflightError(f"Root repository directory does not exist: {sanitize_error(resolved_root)}")

    # 3. Frontend directory and files check
    frontend_dir = resolved_root / "control_tower" / "frontend"
    if not frontend_dir.exists() or not frontend_dir.is_dir():
        raise PreflightError("Frontend directory control_tower/frontend does not exist")

    for fname in REQUIRED_FRONTEND_FILES:
        target = frontend_dir / fname
        if not target.exists() or not target.is_file():
            raise PreflightError(f"Required frontend asset missing: {fname}")

    # 4. Port availability check
    if check_ports:
        if not is_port_available(backend_port, LOOPBACK_IP):
            raise PreflightError(f"PORT_OCCUPIED: Backend loopback port {backend_port} is already in use")
        if not is_port_available(frontend_port, LOOPBACK_IP):
            raise PreflightError(f"PORT_OCCUPIED: Frontend loopback port {frontend_port} is already in use")

    return {
        "status": "PASS",
        "python_version": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
        "root_dir": str(resolved_root),
        "backend_host": LOOPBACK_IP,
        "backend_port": backend_port,
        "frontend_host": LOOPBACK_IP,
        "frontend_port": frontend_port,
        "frontend_files": list(REQUIRED_FRONTEND_FILES),
        "loopback_only": True,
        "read_only": True,
    }
