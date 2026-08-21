"""
Durable Execution Queue Module

Manages directives/runtime/execution_queue.jsonl durable persistence.
Enforces strict sequence: WRITE -> FLUSH -> FSYNC -> CLOSE -> REOPEN -> VERIFY EXACT RECORD.
Detects queue corruption on reload and fails closed.
"""

import os
import json
import hashlib
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, List, Set, Optional, Any
from src.directive.contracts import QueuedDirectiveItem, DirectivePayload, DirectiveEnvelope
from config import settings


class QueuePersistenceError(Exception):
    pass


class QueueCorruptionError(QueuePersistenceError):
    pass


class DurableExecutionQueue:
    def __init__(self, queue_file_path: Optional[Path] = None):
        self.queue_file = queue_file_path or (settings.CONTROL_PLANE_ROOT / "directives" / "runtime" / "execution_queue.jsonl")
        self.queue_file.parent.mkdir(parents=True, exist_ok=True)
        self.queued_items: List[QueuedDirectiveItem] = []
        self.queued_ids: Dict[str, QueuedDirectiveItem] = {}
        self.queue_corrupted: bool = False
        self.corruption_reason: Optional[str] = None
        self._load_queue()

    def _load_queue(self):
        self.queued_items.clear()
        self.queued_ids.clear()
        self.queue_corrupted = False
        self.corruption_reason = None

        if self.queue_file.exists():
            try:
                with open(self.queue_file, "r", encoding="utf-8") as f:
                    for line_no, line in enumerate(f, start=1):
                        line_str = line.strip()
                        if not line_str:
                            continue
                        try:
                            data = json.loads(line_str)
                            d_id = data.get("directive_id")
                            if not d_id:
                                self.queue_corrupted = True
                                self.corruption_reason = f"QUEUE_CORRUPTION: Line {line_no} missing directive_id"
                                raise QueueCorruptionError(self.corruption_reason)

                            if d_id not in self.queued_ids:
                                item = QueuedDirectiveItem(
                                    directive_id=d_id,
                                    directive_source_sha=data.get("directive_source_sha", ""),
                                    directive_blob_sha=data.get("directive_blob_sha", ""),
                                    directive_payload_sha256=data.get("directive_payload_sha256", ""),
                                    accepted_at=data.get("accepted_at", ""),
                                    queue_state=data.get("queue_state", "READY_FOR_FUTURE_EXECUTOR"),
                                    target_project=data.get("target_project", ""),
                                    action_type=data.get("action_type", ""),
                                    requires_human_approval=bool(data.get("requires_human_approval", False)),
                                    executed=bool(data.get("executed", False)),
                                    execution_attempts=int(data.get("execution_attempts", 0)),
                                    readback_verified=bool(data.get("readback_verified", True)),
                                    idempotency_key=data.get("idempotency_key", ""),
                                    signer_identity=data.get("signer_identity", ""),
                                    directive_payload=data.get("directive_payload")
                                )
                                self.queued_items.append(item)
                                self.queued_ids[d_id] = item
                        except json.JSONDecodeError as je:
                            self.queue_corrupted = True
                            self.corruption_reason = f"QUEUE_CORRUPTION: Malformed JSON at line {line_no}: {str(je)}"
                            raise QueueCorruptionError(self.corruption_reason)
            except QueueCorruptionError:
                raise
            except Exception as e:
                self.queue_corrupted = True
                self.corruption_reason = f"QUEUE_CORRUPTION: Queue reload failed: {str(e)}"
                raise QueueCorruptionError(self.corruption_reason)

    def is_queued(self, directive_id: str) -> bool:
        if self.queue_corrupted:
            return False
        return directive_id in self.queued_ids

    def get_queued_item(self, directive_id: str) -> Optional[QueuedDirectiveItem]:
        if self.queue_corrupted:
            return None
        return self.queued_ids.get(directive_id)

    def enqueue_payload(
        self,
        payload: DirectivePayload,
        envelope: DirectiveEnvelope,
        auth_metadata: Dict[str, Any],
        accepted_at: Optional[str] = None
    ) -> QueuedDirectiveItem:
        if self.queue_corrupted:
            raise QueueCorruptionError(self.corruption_reason or "QUEUE_CORRUPTION: Queue file is corrupted")

        d_id = payload.directive_id
        if d_id in self.queued_ids:
            return self.queued_ids[d_id]

        now_iso = accepted_at or datetime.now(timezone.utc).isoformat()
        payload_sha256 = auth_metadata.get("payload_sha256", envelope.payload_sha256)
        blob_sha = auth_metadata.get("payload_blob_sha", envelope.payload_blob_sha)
        signer_id = auth_metadata.get("signer_identity", envelope.signer_identity)
        commit_sha = envelope.payload_commit_sha

        idempotency_raw = f"{d_id}:{commit_sha}:{payload_sha256}".encode("utf-8")
        idempotency_key = hashlib.sha256(idempotency_raw).hexdigest()

        item = QueuedDirectiveItem(
            directive_id=d_id,
            directive_source_sha=commit_sha,
            directive_blob_sha=blob_sha,
            directive_payload_sha256=payload_sha256,
            accepted_at=now_iso,
            queue_state="READY_FOR_FUTURE_EXECUTOR",
            target_project=payload.target_project,
            action_type=payload.action_type,
            requires_human_approval=payload.requires_human_approval,
            executed=False,
            execution_attempts=0,
            readback_verified=False,
            idempotency_key=idempotency_key,
            signer_identity=signer_id,
            directive_payload=payload.to_dict()
        )

        record_json_str = json.dumps(item.to_dict()) + "\n"

        # 1. WRITE -> FLUSH -> FSYNC -> CLOSE
        try:
            self.queue_file.parent.mkdir(parents=True, exist_ok=True)
            with open(self.queue_file, "a", encoding="utf-8") as f:
                f.write(record_json_str)
                f.flush()
                os.fsync(f.fileno())
        except Exception as e:
            raise QueuePersistenceError(f"QUEUE_PERSISTENCE_FAILURE: Failed writing execution queue: {str(e)}")

        # 2. REOPEN -> VERIFY EXACT RECORD
        persisted_ok = False
        try:
            with open(self.queue_file, "r", encoding="utf-8") as f:
                lines = [line.strip() for line in f if line.strip()]
                if lines:
                    last_record = json.loads(lines[-1])
                    if (
                        last_record.get("directive_id") == d_id and
                        last_record.get("idempotency_key") == idempotency_key and
                        last_record.get("directive_payload_sha256") == payload_sha256
                    ):
                        persisted_ok = True
        except Exception as e:
            raise QueuePersistenceError(f"QUEUE_CORRUPTION: Read-back verification failed: {str(e)}")

        if not persisted_ok:
            raise QueuePersistenceError(f"QUEUE_RECORD_MISMATCH: Persisted queue record does not match item {d_id}")

        item.readback_verified = True
        self.queued_items.append(item)
        self.queued_ids[d_id] = item
        return item

    def get_items(self) -> List[QueuedDirectiveItem]:
        if self.queue_corrupted:
            return []
        return list(self.queued_items)
