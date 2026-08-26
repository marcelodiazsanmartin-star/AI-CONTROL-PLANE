"""Bounded deterministic AF-01 scheduler."""
from __future__ import annotations
import time
from .store import AutonomyStore, BlockedError

class Scheduler:
    def __init__(self,store:AutonomyStore,*,batch_size=8,cadence_seconds=1.0,sleeper=time.sleep):
        if isinstance(batch_size,bool) or not isinstance(batch_size,int) or batch_size<=0: raise BlockedError("invalid batch size")
        if cadence_seconds<=0: raise BlockedError("invalid cadence")
        self.store=store; self.batch_size=batch_size; self.cadence_seconds=float(cadence_seconds); self.sleeper=sleeper
        self.status="IDLE"; self.last_loop=None; self.last_error=None
    def schedule_once(self,*,now=None):
        n=self.store.now(now); leases=[]; self.status="RUNNING"; self.last_error=None
        for task in self.store.schedulable_tasks(limit=self.batch_size):
            try:
                worker=self.store.route_or_wait(task["task_id"],now=n)
                if worker: leases.append(self.store.claim(task["task_id"],worker,now=n))
            except Exception as exc:
                self.last_error=type(exc).__name__
        self.last_loop=n; self.status="IDLE"; return leases
    def run(self,iterations,*,clock=time.time):
        if iterations<0: raise BlockedError("invalid iterations")
        results=[]
        for index in range(iterations):
            results.append(self.schedule_once(now=clock()))
            if index+1<iterations:self.sleeper(self.cadence_seconds)
        return results
