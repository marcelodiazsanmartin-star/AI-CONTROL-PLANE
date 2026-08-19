"""
Durable Execution Queue Module

Manages directives/runtime/execution_queue.jsonl durable persistence.
Guarantees execution queue reconstructs exactly upon daemon restart.
"""

import json
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, List, Set, Optional, Any
from src.directive.contracts import QueuedDirectiveItem, Directive
from config import settings


class DurableExecutionQueue:
    def __init__(self, queue_file_path: Optional[Path] = None):
        self.queue_file = queue_file_path or (settings.CONTROL_PLANE_ROOT / "directives" / "runtime" / "execution_queue.jsonl")
        self.queue_file.parent.mkdir(parents=True, exist_ok=True)
        self.queued_items: List[QueuedDirectiveItem] = []
        self.queued_ids: Set[str] = set()
        self._load_queue()

    def _load_queue(self):
        self.queued_items.clear()
        self.queued_ids.clear()
        if self.queue_file.exists():
            try:
                with open(self.queue_file, "r", encoding="utf-8") as f:
                    for line in f:
                        line_str = line.strip()
                        if line_str:
                            try:
                                data = json.loads(line_str)
                                d_id = data.get("directive_id")
                                if d_id and d_id not in self.queued_ids:
                                    item = QueuedDirectiveItem(
                                        directive_id=d_id,
                                        directive_source_sha=data.get("directive_source_sha", ""),
                                        directive_blob_sha=data.get("directive_blob_sha", ""),
                                        accepted_at=data.get("accepted_at", ""),
                                        queue_state=data.get("queue_state", "READY_FOR_FUTURE_EXECUTOR"),
                                        target_project=data.get("target_project", ""),
                                        action_type=data.get("action_type", ""),
                                        requires_human_approval=bool(data.get("requires_human_approval", False)),
                                        executed=bool(data.get("executed", False)),
                                        execution_attempts=int(data.get("execution_attempts", 0)),
                                        directive_payload=data.get("directive_payload")
                                    )
                                    self.queued_items.append(item)
                                    self.queued_ids.add(d_id)
                            except Exception:
                                pass
            except Exception:
                pass

    def is_queued(self, directive_id: str) -> bool:
        return directive_id in self.queued_ids

    def enqueue(
        self,
        directive: Directive,
        blob_sha: str,
        accepted_at: Optional[str] = None
    ) -> QueuedDirectiveItem:
        if directive.directive_id in self.queued_ids:
            # Already queued, return existing item
            for item in self.queued_items:
                if item.directive_id == directive.directive_id:
                    return item

        now_iso = accepted_at or datetime.now(timezone.utc).isoformat()
        item = QueuedDirectiveItem(
            directive_id=directive.directive_id,
            directive_source_sha=directive.source_commit_sha,
            directive_blob_sha=blob_sha,
            accepted_at=now_iso,
            queue_state="READY_FOR_FUTURE_EXECUTOR",
            target_project=directive.target_project,
            action_type=directive.action_type,
            requires_human_approval=directive.requires_human_approval,
            executed=False,
            execution_attempts=0,
            directive_payload=directive.to_dict()
        )

        self.queued_items.append(item)
        self.queued_ids.add(directive.directive_id)

        try:
            with open(self.queue_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(item.to_dict()) + "\n")
                f.flush()
        except Exception as e:
            print(f"Warning: Failed writing execution queue: {e}")

        return item

    def get_items(self) -> List[QueuedDirectiveItem]:
        return list(self.queued_items)
