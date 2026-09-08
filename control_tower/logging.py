"""Tower-owned structured operational logging with secret redaction and bounded retention."""

from __future__ import annotations

import json
import threading
import time
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from control_tower.security import sanitize_error

MAX_LOG_ENTRIES = 500


class StructuredLogger:
    """Thread-safe structured operational logger for CONTROL TOWER."""

    def __init__(self, max_entries: int = MAX_LOG_ENTRIES) -> None:
        self._lock = threading.Lock()
        self._records: deque[dict[str, Any]] = deque(maxlen=max_entries)

    def log(
        self,
        component: str,
        result_class: str,
        request_id: str | None = None,
        latency_ms: float | None = None,
        error_code: str | None = None,
        error_detail: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Record a structured sanitized log entry."""
        now = datetime.now(timezone.utc)
        record: dict[str, Any] = {
            "timestamp": now.isoformat(),
            "component": component,
            "result_class": result_class,
            "request_id": request_id,
            "latency_ms": round(latency_ms, 2) if latency_ms is not None else None,
            "error_code": error_code,
            "error_detail": sanitize_error(error_detail) if error_detail else None,
        }
        if metadata:
            sanitized_meta = {}
            for k, v in metadata.items():
                if isinstance(v, str):
                    sanitized_meta[k] = sanitize_error(v)
                elif isinstance(v, (int, float, bool)):
                    sanitized_meta[k] = v
                else:
                    sanitized_meta[k] = sanitize_error(str(v))
            record["metadata"] = sanitized_meta

        with self._lock:
            self._records.append(record)
        return record

    def get_recent(self, limit: int = 50) -> list[dict[str, Any]]:
        """Return a copy of recent sanitized log records."""
        with self._lock:
            return list(self._records)[-limit:]

    def clear(self) -> None:
        """Clear log entries (for tests)."""
        with self._lock:
            self._records.clear()


# Global Tower operational logger singleton
tower_logger = StructuredLogger()
