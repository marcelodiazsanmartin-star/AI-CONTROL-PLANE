"""Deterministic AF-02 router over canonical task, worker and lease truth."""
from __future__ import annotations
import math

from .gateway import LocalWorkerGateway
from .store import AutonomyStore, BlockedError, IntegrityBlockedError, clean


class AgentRouter:
    def __init__(
        self,
        store: AutonomyStore,
        gateway: LocalWorkerGateway,
        *,
        batch_size: int = 8,
        lease_seconds: float = 30.0,
    ):
        if isinstance(batch_size, bool) or not isinstance(batch_size, int) or batch_size <= 0:
            raise BlockedError("invalid router batch size")
        if (
            isinstance(lease_seconds, bool)
            or not isinstance(lease_seconds, (int, float))
            or not math.isfinite(float(lease_seconds))
            or lease_seconds <= 0
        ):
            raise BlockedError("invalid lease duration")
        self.store = store
        self.gateway = gateway
        self.batch_size = batch_size
        self.lease_seconds = float(lease_seconds)
        self.status = "IDLE"
        self.last_route: dict[str, object] | None = None
        self.last_error: str | None = None

    def route_once(self, *, now: float) -> list[object]:
        n = self.store.now(now)
        dispatched = []
        self.status = "ROUTING"
        self.last_error = None
        for task in self.store.schedulable_tasks(limit=self.batch_size):
            try:
                candidates = self.gateway.eligible_sessions(
                    capability=task["capability"],
                    target_project=task["target_project"],
                    now=n,
                )
                if not candidates:
                    self.store.mark_waiting_capacity(task["task_id"], now=n)
                    continue
                worker_id, session_id = candidates[0]
                lease = self.store.claim(
                    task["task_id"],
                    worker_id,
                    lease_seconds=self.lease_seconds,
                    now=n,
                )
                reason = "capability_target_freshness_capacity_worker_session"
                self.store.audit(
                    task["task_id"],
                    "ROUTED",
                    n,
                    f"worker={worker_id};session={session_id};lease={lease['lease_id']};reason={reason}",
                )
                envelope = self.gateway.dispatch(
                    task, lease, session_id=session_id, now=n
                )
                dispatched.append(envelope)
                self.last_route = {
                    "task_id": task["task_id"],
                    "worker_id": worker_id,
                    "session_id": session_id,
                    "lease_id": lease["lease_id"],
                    "reason": reason,
                }
            except BlockedError as exc:
                self.last_error = clean(type(exc).__name__)
            except Exception as exc:
                self.last_error = clean(type(exc).__name__)
                self.status = "ERROR"
                raise
        self.status = "IDLE"
        return dispatched

    def health_projection(self, *, now: float) -> dict[str, object]:
        n = self.store.now(now)
        try:
            counts = self.store.state_counts()
            leases = self.store.active_leases(now=n)
            dispatches = {
                item["lease_id"]: item for item in self.gateway.dispatch_projection()
            }
            active = []
            for lease in leases:
                dispatch = dispatches.get(lease["lease_id"])
                active.append(
                    {
                        "task_id": lease["task_id"],
                        "worker_id": lease["assigned_worker_id"],
                        "lease_id": lease["lease_id"],
                        "expires_at": lease["lease_expires_at"],
                        "expired": lease["expired"],
                        "dispatch_status": (
                            "UNKNOWN"
                            if dispatch is None
                            else "ACKED"
                            if dispatch["acknowledged"]
                            else "DISPATCHED"
                        ),
                    }
                )
            return {
                "router": {
                    "status": self.status,
                    "last_route": self.last_route or "UNKNOWN",
                    "last_error": self.last_error or "UNKNOWN",
                },
                "external_workers": self.gateway.session_projection(now=n),
                "active_leases": active,
                "counts": {
                    key: counts[key]
                    for key in (
                        "QUEUED",
                        "WAITING_CAPACITY",
                        "RUNNING",
                        "RETRYING",
                        "DEAD_LETTER",
                    )
                },
            }
        except Exception:
            return {
                "router": {
                    "status": "UNKNOWN",
                    "last_route": "UNKNOWN",
                    "last_error": "INTEGRITY_BLOCKED",
                },
                "external_workers": [],
                "active_leases": [],
                "counts": "UNKNOWN",
            }
