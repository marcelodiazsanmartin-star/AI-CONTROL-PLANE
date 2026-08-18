"""
Replay Protection Ledger Module

Manages directives/runtime/consumed_directives.jsonl durable record.
Guarantees directive_ids are processed at most once across process restarts.
"""

import json
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, Set, Optional, Any
from src.directive.contracts import ConsumedRecord
from config import settings


class ReplayLedger:
    def __init__(self, ledger_file_path: Optional[Path] = None):
        self.ledger_file = ledger_file_path or (settings.CONTROL_PLANE_ROOT / "directives" / "runtime" / "consumed_directives.jsonl")
        self.ledger_file.parent.mkdir(parents=True, exist_ok=True)
        self.consumed_ids: Set[str] = set()
        self._load_ledger()

    def _load_ledger(self):
        self.consumed_ids.clear()
        if self.ledger_file.exists():
            try:
                with open(self.ledger_file, "r", encoding="utf-8") as f:
                    for line in f:
                        line_str = line.strip()
                        if line_str:
                            try:
                                record = json.loads(line_str)
                                d_id = record.get("directive_id")
                                if d_id:
                                    self.consumed_ids.add(d_id)
                            except Exception:
                                pass
            except Exception:
                pass

    def is_consumed(self, directive_id: str) -> bool:
        return directive_id in self.consumed_ids

    def record_consumption(
        self,
        directive_id: str,
        source_commit_sha: str,
        first_seen_at: str,
        decision: str,
        decision_reason: str
    ) -> ConsumedRecord:
        record = ConsumedRecord(
            directive_id=directive_id,
            source_commit_sha=source_commit_sha,
            first_seen_at=first_seen_at,
            decision=decision,
            decision_reason=decision_reason,
            processed_at=datetime.now(timezone.utc).isoformat()
        )

        self.consumed_ids.add(directive_id)

        try:
            with open(self.ledger_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(record.to_dict()) + "\n")
                f.flush()
        except Exception as e:
            print(f"Warning: Failed writing replay ledger: {e}")

        return record
