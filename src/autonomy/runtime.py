"""AF-04 separately runnable, fail-closed Autonomy Foundation runtime."""
from __future__ import annotations

import os
import sqlite3
import time
from pathlib import Path
from typing import Callable, Iterable

from config import settings

from .execution import DisposableWorkspaceRegistry, GovernedExecutionController
from .gateway import LocalWorkerGateway
from .ingestion import DirectiveTaskIngestor, ProvenanceVerifier
from .router import AgentRouter
from .store import AutonomyStore, BlockedError, IntegrityBlockedError, clean
from .supervisor import Supervisor

CONTROL_PLANE_EXECUTE_MUTATING_DIRECTIVES = False
FILE_ATTRIBUTE_REPARSE_POINT = 0x400


def _contains(root: Path, candidate: Path) -> bool:
    try:
        candidate.relative_to(root)
        return True
    except ValueError:
        return False


class RuntimeRootPolicy:
    """Requires an explicit disposable root physically outside every protected repository."""

    def __init__(self, forbidden_roots: Iterable[Path | str]):
        self.forbidden_roots = tuple(Path(item).resolve(strict=True) for item in forbidden_roots)

    def validate(self, root: Path | str) -> Path:
        requested = Path(root)
        if not requested.exists() or not requested.is_dir() or requested.is_symlink():
            raise BlockedError("explicit runtime root unavailable")
        resolved = requested.resolve(strict=True)
        if os.path.normcase(str(requested.absolute())) != os.path.normcase(str(resolved)):
            raise BlockedError("runtime root contains symlink or reparse traversal")
        stat = resolved.stat(follow_symlinks=False)
        if int(getattr(stat, "st_file_attributes", 0)) & FILE_ATTRIBUTE_REPARSE_POINT:
            raise BlockedError("reparse runtime root")
        for forbidden in self.forbidden_roots:
            if _contains(forbidden, resolved) or _contains(resolved, forbidden):
                raise BlockedError("runtime root intersects protected repository")
        return resolved


class AutonomyRuntime:
    """Deterministic composition layer. It is never imported or started by main.py."""

    def __init__(self, *, runtime_root: Path | str, queue_path: Path | str,
                 repository_roots: Iterable[Path | str], supported_targets: Iterable[str],
                 verifier: ProvenanceVerifier | None, profiles=(), workspaces=None,
                 clock: Callable[[], float] = time.time):
        roots = tuple(repository_roots)
        if not roots:
            raise BlockedError("repository roots required")
        self.root = RuntimeRootPolicy(roots).validate(runtime_root)
        self.clock = clock
        self.store = AutonomyStore(self.root / "autonomy.sqlite")
        self.gateway = LocalWorkerGateway(self.store, tuple(profiles))
        self.router = AgentRouter(self.store, self.gateway)
        self.supervisor = Supervisor(self.store)
        registry = workspaces or DisposableWorkspaceRegistry(real_repository_root=roots[0])
        self.execution = GovernedExecutionController(self.store, self.gateway, registry, clock=clock)
        self.ingestor = DirectiveTaskIngestor(self.store, queue_path, verifier=verifier,
                                              supported_targets=supported_targets, clock=clock)
        self._init_schema()

    def _init_schema(self) -> None:
        self.store.db.executescript("""
CREATE TABLE IF NOT EXISTS autonomy_runtime_state(
 singleton INTEGER PRIMARY KEY CHECK(singleton=1),status TEXT NOT NULL,
 cycle_count INTEGER NOT NULL,last_cycle_at REAL,last_error TEXT,
 store_integrity TEXT NOT NULL,last_stage TEXT NOT NULL);
INSERT OR IGNORE INTO autonomy_runtime_state VALUES(1,'IDLE',0,NULL,NULL,'UNKNOWN','INITIALIZED');
""")

    def _state(self, *, status: str, now: float, stage: str, error: str | None = None, increment: bool = False) -> None:
        self.store.db.execute("UPDATE autonomy_runtime_state SET status=?,last_cycle_at=?,last_error=?,store_integrity=?,last_stage=?,cycle_count=cycle_count+? WHERE singleton=1",
                              (status, now, clean(error) if error else None,
                               "VERIFIED" if status != "INTEGRITY_BLOCKED" else "INTEGRITY_BLOCKED",
                               stage, int(increment)))

    def _verify_store(self) -> None:
        row = self.store.db.execute("PRAGMA quick_check").fetchone()
        if not row or row[0] != "ok":
            raise IntegrityBlockedError("store integrity failure")

    def _recover(self, now: float) -> list[dict[str, str]]:
        outcomes = []
        rows = self.store.db.execute("SELECT g.grant_id,g.workspace_id,w.state FROM execution_grants g LEFT JOIN execution_workspaces w ON w.workspace_id=g.workspace_id WHERE g.state='APPLYING' ORDER BY g.grant_id").fetchall()
        known = {item.workspace_id for item in self.execution.workspaces.descriptors()}
        for row in rows:
            if row[1] not in known or row[2] != "AVAILABLE":
                outcomes.append({"grant_id": row[0], "state": "UNKNOWN"})
                continue
            try:
                outcomes.append({"grant_id": row[0], "state": self.execution.recover(row[0], now=now)})
            except BlockedError:
                outcomes.append({"grant_id": row[0], "state": "INTEGRITY_BLOCKED"})
        return outcomes

    def run_once(self, *, now: float | None = None) -> dict[str, object]:
        n = self.store.now(self.clock() if now is None else now)
        try:
            self._verify_store()
            self._state(status="RUNNING", now=n, stage="STORE_VERIFIED")
            ingested = self.ingestor.ingest()
            self._state(status="RUNNING", now=n, stage="INGESTED")
            reconciled = self.supervisor.reconcile(now=n)
            self._state(status="RUNNING", now=n, stage="RECONCILED")
            recovered = self._recover(n)
            self._state(status="RUNNING", now=n, stage="RECOVERED")
            routed = self.router.route_once(now=n)
            self._state(status="IDLE", now=n, stage="PROJECTED", increment=True)
            return {"ingested": [item.task_id for item in ingested], "reconciled": reconciled,
                    "recovered": recovered, "routed": [item.task_id for item in routed],
                    "projection": self.projection(now=n)}
        except IntegrityBlockedError as exc:
            self._state(status="INTEGRITY_BLOCKED", now=n, stage="FAILED", error=type(exc).__name__, increment=True)
            raise
        except BlockedError as exc:
            self._state(status="BLOCKED", now=n, stage="FAILED", error=type(exc).__name__, increment=True)
            raise
        except Exception as exc:
            self._state(status="ERROR", now=n, stage="HARNESS_ERROR", error=type(exc).__name__, increment=True)
            raise

    def run_bounded(self, cycles: int, *, cadence_seconds: float = 0,
                    sleeper: Callable[[float], None] = time.sleep) -> list[dict[str, object]]:
        if isinstance(cycles, bool) or not isinstance(cycles, int) or cycles <= 0 or cycles > 10_000:
            raise BlockedError("invalid cycle bound")
        results = []
        for index in range(cycles):
            results.append(self.run_once())
            if index + 1 < cycles and cadence_seconds:
                sleeper(cadence_seconds)
        return results

    def projection(self, *, now: float | None = None) -> dict[str, object]:
        n = self.store.now(self.clock() if now is None else now)
        state = self.store.db.execute("SELECT status,cycle_count,last_cycle_at,last_error,store_integrity,last_stage FROM autonomy_runtime_state WHERE singleton=1").fetchone()
        counts = self.store.state_counts()
        leases = [{key: item[key] for key in ("task_id","assigned_worker_id","lease_id","lease_expires_at","state","expired")} for item in self.store.active_leases(now=n)]
        return {
            "runtime": dict(state) if state else {"status": "UNKNOWN"},
            "ingestion": self.ingestor.projection(),
            "tasks": counts,
            "active_leases": leases,
            "workers": self.gateway.session_projection(now=n),
            "router": self.router.health_projection(now=n)["router"],
            "execution": self.execution.projection(now=n),
            "retry_count": counts["RETRYING"], "dead_letter_count": counts["DEAD_LETTER"],
            "safety": {"real_project_mutation_enabled": False,
                       "control_plane_execute_mutating_directives": settings.CONTROL_PLANE_EXECUTE_MUTATING_DIRECTIVES},
        }
