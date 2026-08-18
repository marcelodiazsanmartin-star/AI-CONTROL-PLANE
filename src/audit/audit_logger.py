"""
Audit Logger Module

Append-only audit trail logger writing structured JSONL events to audit/events.jsonl.
"""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, Optional
from src.contracts import NormalizedProjectState


class AuditLogger:
    def __init__(self, audit_file_path: Path):
        self.audit_file_path = audit_file_path
        self.audit_file_path.parent.mkdir(parents=True, exist_ok=True)

    def log_observation_event(self, state: NormalizedProjectState, previous_status: Optional[str] = None):
        event = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": "PROJECT_OBSERVED",
            "project": state.project,
            "status": state.status.value if hasattr(state.status, "value") else str(state.status),
            "previous_status": previous_status,
            "state_conflict": state.state_conflict,
            "conflicting_sources": state.conflicting_sources,
            "reason": state.reason,
            "confidence": state.confidence,
            "stage": state.stage,
            "branch": state.branch,
            "local_head": state.local_head,
            "process_running": state.process_running,
            "heartbeat_age_seconds": state.heartbeat_age_seconds,
            "evidence_sources": state.evidence_sources
        }

        with open(self.audit_file_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(event) + "\n")
