"""
AI-CONTROL-PLANE Main Entrypoint

Supports:
- py -3 main.py --once     (Single read-only observation sweep)
- py -3 main.py            (Persistent observer loop polling every CONTROL_PLANE_POLL_SECONDS)
"""

import sys
import time
import argparse
from pathlib import Path

# Add project root to sys.path
root_dir = Path(__file__).resolve().parent
if str(root_dir) not in sys.path:
    sys.path.insert(0, str(root_dir))

from config import settings
from src.engine import ControlPlaneEngine


def run_once(engine: ControlPlaneEngine):
    states = engine.run_sweep()
    print("==================================================")
    print("AI-CONTROL-PLANE SINGLE OBSERVATION SWEEP COMPLETE")
    print("==================================================")
    for proj_name, state in states.items():
        print(f"Project: {proj_name}")
        print(f"  Canonical Status: {state.status.value}")
        print(f"  Reason:           {state.reason}")
        print(f"  State Conflict:   {state.state_conflict}")
        if state.conflicting_sources:
            print(f"  Conflicts:        {state.conflicting_sources}")
        print(f"  Status Source:    {state.status_source}")
        print(f"  Head Verification: {state.verified_head.to_dict() if state.verified_head else 'N/A'}")
        print(f"  Process Running:  {state.process_running}")
        print("--------------------------------------------------")


def run_continuous(engine: ControlPlaneEngine):
    poll_interval = settings.CONTROL_PLANE_POLL_SECONDS
    print("==================================================")
    print(f"AI-CONTROL-PLANE PERSISTENT OBSERVER STARTED (poll={poll_interval}s)")
    print("==================================================")
    try:
        while True:
            states = engine.run_sweep()
            print(f"[{engine.started_at}] Sweep #{engine.sweep_count} complete — Monitored: {len(states)}")
            time.sleep(poll_interval)
    except KeyboardInterrupt:
        print("\nStopping Control Plane Observer gracefully...")
        engine.update_self_health(status_str="STOPPED")


def main():
    parser = argparse.ArgumentParser(description="AI-CONTROL-PLANE Observer")
    parser.add_argument("--once", action="store_true", help="Run a single observation sweep and exit")
    args = parser.parse_args()

    engine = ControlPlaneEngine()

    if args.once:
        run_once(engine)
    else:
        run_continuous(engine)


if __name__ == "__main__":
    main()
