"""Command-line entrypoint for CONTROL TOWER CT-03 service."""

from __future__ import annotations

import signal
import sys
import time

from control_tower.preflight import PreflightError
from control_tower.security import sanitize_error
from control_tower.service import ControlTowerService


def main() -> int:
    """Run CONTROL TOWER backend and frontend service."""
    service = ControlTowerService()

    def handle_signal(signum, frame):
        print("\n[CONTROL TOWER] Shutting down gracefully...")
        service.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    try:
        info = service.start()
        print("==================================================")
        print(" CONTROL TOWER — OPERATIONAL READ-ONLY DASHBOARD ")
        print("==================================================")
        print(f" Frontend: {info['frontend_url']}")
        print(f" Backend:  {info['backend_url']}/api/v1/dashboard")
        print(f" Liveness: {info['backend_url']}/health")
        print(f" Ready:    {info['backend_url']}/ready")
        print(" Status:   ACTIVE (Press Ctrl+C to stop)")
        print("==================================================")

        while service.is_running:
            time.sleep(1)
        return 0
    except PreflightError as pe:
        print(f"[CONTROL TOWER ERROR] Preflight failed: {sanitize_error(pe)}", file=sys.stderr)
        service.stop()
        return 1
    except Exception as e:
        print(f"[CONTROL TOWER ERROR] Startup failed: {sanitize_error(e)}", file=sys.stderr)
        service.stop()
        return 1


if __name__ == "__main__":
    sys.exit(main())
