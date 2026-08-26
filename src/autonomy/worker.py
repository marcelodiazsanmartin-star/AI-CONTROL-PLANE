"""Provider-neutral, read-only worker contract for AF-01."""
from __future__ import annotations
from dataclasses import dataclass
from typing import Protocol
from .store import BlockedError, clean

@dataclass(frozen=True)
class WorkerResult:
    evidence_id: str
    evidence_sha256: str
    summary: str = ""

class WorkerAdapter(Protocol):
    worker_id: str
    kind: str
    capabilities: tuple[str, ...]
    targets: tuple[str, ...]
    capacity: int
    heartbeat_sla: float
    def accept(self, task: dict[str, object], lease: dict[str, object]) -> WorkerResult: ...

class ReadOnlyTestWorker:
    """Deterministic in-process adapter; it cannot mutate projects or call providers."""
    def __init__(self,worker_id="readonly-test",*,capabilities=("READ",),targets=("TEST",),capacity=1,heartbeat_sla=30.0,fail=False):
        if capacity<0 or heartbeat_sla<=0: raise BlockedError("invalid worker adapter")
        self.worker_id=clean(worker_id); self.kind="in-process-read-only-test"
        self.capabilities=tuple(capabilities); self.targets=tuple(targets)
        self.capacity=int(capacity); self.heartbeat_sla=float(heartbeat_sla); self.fail=fail
    def accept(self,task,lease):
        if self.fail: raise BlockedError("read-only worker failure")
        if lease.get("worker_id")!=self.worker_id or lease.get("task_id")!=task.get("task_id"): raise BlockedError("lease ownership mismatch")
        payload=f"{task['task_id']}|{lease['lease_id']}|READ_ONLY".encode()
        from .store import AutonomyStore
        return WorkerResult("readonly:"+clean(task["task_id"]),AutonomyStore.evidence_hash(payload),"READ_ONLY_RESULT")
