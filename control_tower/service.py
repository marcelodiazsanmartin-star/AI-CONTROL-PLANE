"""Unified local service manager for CONTROL TOWER CT-03."""

from __future__ import annotations

import signal
import sys
import threading
import time
from pathlib import Path
from typing import Any

from control_tower.api import create_server as create_backend_server
from control_tower.frontend_server import create_frontend_server
from control_tower.logging import tower_logger
from control_tower.preflight import PreflightError, run_preflight
from control_tower.resilience import resilient_executor
from control_tower.security import sanitize_error


class ControlTowerService:
    """Manages backend (8000) and frontend (3000) loopback servers together."""

    def __init__(
        self,
        backend_port: int = 8000,
        frontend_port: int = 3000,
        root_dir: Path | None = None,
    ) -> None:
        self.backend_port = backend_port
        self.frontend_port = frontend_port
        self.root_dir = root_dir
        self.backend_server = None
        self.frontend_server = None
        self._backend_thread = None
        self._frontend_thread = None
        self._is_running = False
        self._lock = threading.Lock()

    def start(self, check_ports: bool = True) -> dict[str, Any]:
        """Execute preflight and start both backend and frontend servers."""
        with self._lock:
            if self._is_running:
                return {"status": "ALREADY_RUNNING"}

            # Run preflight
            preflight_info = run_preflight(
                root_dir=self.root_dir,
                backend_port=self.backend_port,
                frontend_port=self.frontend_port,
                check_ports=check_ports,
            )

            # Create servers with root_dir passed
            self.backend_server = create_backend_server(port=self.backend_port, root_dir=self.root_dir)
            self.frontend_server = create_frontend_server(port=self.frontend_port, root_dir=self.root_dir)

            # Start threads
            self._backend_thread = threading.Thread(
                target=self.backend_server.serve_forever,
                name="TowerBackendThread",
                daemon=True,
            )
            self._frontend_thread = threading.Thread(
                target=self.frontend_server.serve_forever,
                name="TowerFrontendThread",
                daemon=True,
            )

            self._backend_thread.start()
            self._frontend_thread.start()
            self._is_running = True

            tower_logger.log(
                component="SERVICE",
                result_class="STARTED",
                metadata={
                    "backend_port": self.backend_port,
                    "frontend_port": self.frontend_port,
                },
            )

            return {
                "status": "RUNNING",
                "backend_url": f"http://127.0.0.1:{self.backend_port}",
                "frontend_url": f"http://127.0.0.1:{self.frontend_port}",
                "preflight": preflight_info,
            }

    def stop(self) -> None:
        """Gracefully stop both servers, joined threads, and release sockets."""
        with self._lock:
            if not self._is_running:
                return

            if self.backend_server:
                self.backend_server.shutdown()
                self.backend_server.server_close()
            if self.frontend_server:
                self.frontend_server.shutdown()
                self.frontend_server.server_close()

            if self._backend_thread:
                self._backend_thread.join(timeout=2)
            if self._frontend_thread:
                self._frontend_thread.join(timeout=2)

            resilient_executor.shutdown(wait=False)

            self._is_running = False
            self.backend_server = None
            self.frontend_server = None
            self._backend_thread = None
            self._frontend_thread = None

            tower_logger.log(
                component="SERVICE",
                result_class="STOPPED",
            )

    @property
    def is_running(self) -> bool:
        with self._lock:
            return self._is_running
