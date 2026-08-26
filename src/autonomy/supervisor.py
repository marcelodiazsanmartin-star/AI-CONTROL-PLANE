"""Restart-safe AF-01 supervisor and read-only health projection."""
from __future__ import annotations
from .scheduler import Scheduler
from .store import AutonomyStore, BlockedError, clean

class Supervisor:
    def __init__(self,store:AutonomyStore,adapters=(),*,batch_size=8,cadence_seconds=1.0,sleeper=None):
        self.store=store; self.adapters={adapter.worker_id:adapter for adapter in adapters}
        kwargs={} if sleeper is None else {"sleeper":sleeper}
        self.scheduler=Scheduler(store,batch_size=batch_size,cadence_seconds=cadence_seconds,**kwargs)
    def register_adapters(self,*,now=None):
        n=self.store.now(now)
        for adapter in self.adapters.values():
            self.store.register_worker(worker_id=adapter.worker_id,kind=adapter.kind,capabilities=adapter.capabilities,targets=adapter.targets,heartbeat_sla=adapter.heartbeat_sla,capacity=adapter.capacity,now=n)
    def reconcile(self,*,now=None):
        n=self.store.now(now); changed=[]
        changed.extend(self.store.reconcile_stale_workers(now=n))
        for task_id in self.store.expired_lease_tasks(now=n):
            try:self.store.reclaim_expired(task_id,now=n); changed.append(task_id)
            except BlockedError:pass
        return sorted(set(changed))
    def run_once(self,*,now=None):
        n=self.store.now(now); errors=[]; self.reconcile(now=n); leases=self.scheduler.schedule_once(now=n)
        for lease in leases:
            adapter=self.adapters.get(lease["worker_id"])
            if adapter is None: errors.append((lease["task_id"],"ADAPTER_NOT_CONNECTED")); continue
            try:
                current=self.store.task(lease["task_id"])
                if current["lease_id"]!=lease["lease_id"] or self.store.worker_status(adapter.worker_id,now=n)["status"]!="AVAILABLE": raise BlockedError("lease or worker truth lost")
                self.store.start(lease["task_id"],adapter.worker_id,lease["lease_id"],now=n)
                result=adapter.accept(current,lease)
                self.store.submit_result(lease["task_id"],adapter.worker_id,lease["lease_id"],evidence_id=result.evidence_id,sha256=result.evidence_sha256,now=n)
            except Exception as exc:
                errors.append((lease["task_id"],clean(type(exc).__name__)))
                try:self.store.fail_attempt(lease["task_id"],lease["worker_id"],lease["lease_id"],reason="worker adapter failed",error_code=type(exc).__name__,now=n)
                except BlockedError:pass
        return {"leases":leases,"errors":errors}
    def health_snapshot(self,*,now=None):
        n=self.store.now(now); counts=self.store.state_counts(); workers=[]
        for raw in self.store.workers(now=n):
            workers.append({key:raw[key] for key in ("worker_id","kind","status","capacity","active_lease_count","heartbeat_sla","last_heartbeat")})
        leases=[]
        for raw in self.store.active_leases(now=n):
            leases.append({"task_id":raw["task_id"],"worker_id":raw["assigned_worker_id"],"state":raw["state"],"expires_at":raw["lease_expires_at"],"expired":raw["expired"],"heartbeat_age":None if raw["last_worker_heartbeat"] is None else max(0,n-raw["last_worker_heartbeat"])})
        return {"scheduler":{"status":self.scheduler.status,"last_loop":self.scheduler.last_loop,"last_error":self.scheduler.last_error or "UNKNOWN"},"counts":{key:counts[key] for key in ("QUEUED","WAITING_CAPACITY","RUNNING","RETRYING","DEAD_LETTER")},"workers":workers,"active_leases":leases}
