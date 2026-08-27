"""AF-03 governed mutation transactions for trusted disposable workspaces only."""
from __future__ import annotations

import hashlib
import json
import math
import os
import re
import sqlite3
import time
import unicodedata
import uuid
from dataclasses import dataclass
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Callable, Iterable

from .gateway import LocalWorkerGateway
from .store import AutonomyStore, BlockedError, IntegrityBlockedError, clean

REAL_PROJECT_MUTATION_ENABLED = False
MAX_PLAN_FILES = 64
MAX_PLAN_BYTES = 1_048_576
GRANT_STATES = {"ISSUED", "APPLYING", "APPLIED", "FAILED", "EXPIRED", "INTEGRITY_BLOCKED"}
PROTECTED_PREFIXES = ("state", "reports", "directives/audit", ".git")
FILE_ATTRIBUTE_REPARSE_POINT = 0x400
_HEX = re.compile(r"[0-9a-f]{64}")
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")


@dataclass(frozen=True)
class FileOperation:
    operation: str
    path: str
    expected_preimage: str
    desired_postimage: str
    content: bytes | None = None


@dataclass(frozen=True)
class ExecutionPlan:
    grant_id: str
    operations: tuple[FileOperation, ...]


@dataclass(frozen=True)
class WorkspaceDescriptor:
    workspace_id: str
    root: Path
    target_project: str
    physical_id: str
    kind: str = "DISPOSABLE"


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _safe_id(value: object, name: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", value):
        raise BlockedError(f"invalid {name}")
    return value


def _normalized_relative(value: object) -> str:
    if not isinstance(value, str) or not value or _CONTROL.search(value):
        raise BlockedError("invalid path")
    if unicodedata.normalize("NFC", value) != value or "\\" in value:
        raise BlockedError("malformed path")
    if re.search(r"(?i)(token|secret|password|authorization)\s*[:=]", value):
        raise BlockedError("secret-shaped path metadata")
    posix = PurePosixPath(value)
    windows = PureWindowsPath(value)
    if posix.is_absolute() or windows.is_absolute() or windows.drive or any(part in ("", ".", "..") for part in posix.parts):
        raise BlockedError("path escape")
    normalized = posix.as_posix()
    return normalized


def _physical_id(path: Path) -> str:
    stat = path.stat(follow_symlinks=False)
    attributes = int(getattr(stat, "st_file_attributes", 0))
    if attributes & FILE_ATTRIBUTE_REPARSE_POINT:
        raise IntegrityBlockedError("reparse-point workspace")
    return f"{int(stat.st_dev)}:{int(stat.st_ino)}"


def _is_reparse(stat: os.stat_result) -> bool:
    return bool(int(getattr(stat, "st_file_attributes", 0)) & FILE_ATTRIBUTE_REPARSE_POINT)


class DisposableWorkspaceRegistry:
    """Control-plane-owned authority; workers cannot register or rebind roots."""

    def __init__(self, *, real_repository_root: Path | str,
                 protected_paths: Iterable[str] = PROTECTED_PREFIXES):
        self.real_repository_root = Path(real_repository_root).resolve(strict=True)
        self.protected_paths = tuple(sorted({_normalized_relative(item).casefold() for item in protected_paths}))
        self._workspaces: dict[str, WorkspaceDescriptor] = {}
        self._blocked: set[str] = set()

    @staticmethod
    def _contains(root: Path, candidate: Path) -> bool:
        try:
            candidate.relative_to(root)
            return True
        except ValueError:
            return False

    def register_local_disposable(self, *, workspace_id: str, root: Path | str, target_project: str) -> WorkspaceDescriptor:
        ident = _safe_id(workspace_id, "workspace_id")
        project = _safe_id(target_project, "target_project")
        requested = Path(root)
        if not requested.exists() or not requested.is_dir() or requested.is_symlink():
            raise BlockedError("workspace root unavailable")
        resolved = requested.resolve(strict=True)
        if self._contains(self.real_repository_root, resolved) or self._contains(resolved, self.real_repository_root):
            raise BlockedError("real repository workspace prohibited")
        descriptor = WorkspaceDescriptor(ident, resolved, project, _physical_id(resolved))
        existing = self._workspaces.get(ident)
        if existing is not None and existing != descriptor:
            self._blocked.add(ident)
            raise IntegrityBlockedError("workspace authority rebind")
        self._workspaces[ident] = descriptor
        return descriptor

    def resolve(self, workspace_id: str, target_project: str) -> WorkspaceDescriptor:
        ident = _safe_id(workspace_id, "workspace_id")
        descriptor = self._workspaces.get(ident)
        if descriptor is None or ident in self._blocked:
            raise IntegrityBlockedError("workspace authority unavailable")
        if descriptor.target_project != target_project or descriptor.kind != "DISPOSABLE":
            raise BlockedError("workspace target mismatch")
        if (not descriptor.root.exists() or descriptor.root.is_symlink()
                or descriptor.root.resolve(strict=True) != descriptor.root
                or _physical_id(descriptor.root) != descriptor.physical_id):
            self._blocked.add(ident)
            raise IntegrityBlockedError("workspace identity changed")
        return descriptor

    def descriptors(self) -> tuple[WorkspaceDescriptor, ...]:
        return tuple(self._workspaces[key] for key in sorted(self._workspaces))

    def path_allowed(self, relative: str) -> bool:
        folded = relative.casefold()
        return not any(folded == prefix or folded.startswith(prefix + "/") for prefix in self.protected_paths)

    def block(self, workspace_id: str) -> None:
        self._blocked.add(workspace_id)

    def state(self, workspace_id: str) -> str:
        if workspace_id in self._blocked:
            return "INTEGRITY_BLOCKED"
        return "AVAILABLE" if workspace_id in self._workspaces else "UNKNOWN"


class GovernedExecutionController:
    """Single-use execution grants and fail-closed disposable file transactions."""

    def __init__(self, store: AutonomyStore, gateway: LocalWorkerGateway,
                 workspaces: DisposableWorkspaceRegistry, *, clock: Callable[[], float] = time.time):
        self.store = store
        self.gateway = gateway
        self.workspaces = workspaces
        self._clock = clock
        self.status = "IDLE"
        self.last_error: str | None = None
        self._init_schema()

    def _init_schema(self) -> None:
        self.store.db.executescript("""
CREATE TABLE IF NOT EXISTS execution_grants(
 grant_id TEXT PRIMARY KEY, task_id TEXT NOT NULL, worker_id TEXT NOT NULL,
 session_id TEXT NOT NULL, lease_id TEXT NOT NULL, workspace_id TEXT NOT NULL,
 target_project TEXT NOT NULL, capability TEXT NOT NULL, operations TEXT NOT NULL,
 path_prefixes TEXT NOT NULL, issued_at REAL NOT NULL, expires_at REAL NOT NULL,
 consumed_at REAL, state TEXT NOT NULL, plan_hash TEXT);
CREATE TABLE IF NOT EXISTS execution_transactions(
 grant_id TEXT PRIMARY KEY, plan_hash TEXT NOT NULL, operations_manifest TEXT NOT NULL,
 state TEXT NOT NULL, started_at REAL NOT NULL, finished_at REAL,
 evidence_sha256 TEXT, error_code TEXT, evidence_envelope TEXT);
CREATE TABLE IF NOT EXISTS execution_workspaces(
 workspace_id TEXT PRIMARY KEY,root TEXT NOT NULL,physical_id TEXT NOT NULL,
 target_project TEXT NOT NULL,kind TEXT NOT NULL,state TEXT NOT NULL,
 last_verified_at REAL,last_error TEXT);
""")
        columns = {row[1] for row in self.store.db.execute("PRAGMA table_info(execution_transactions)")}
        if "evidence_envelope" not in columns:
            self.store.db.execute("ALTER TABLE execution_transactions ADD COLUMN evidence_envelope TEXT")
        for descriptor in self.workspaces.descriptors():
            row = self.store.db.execute("SELECT * FROM execution_workspaces WHERE workspace_id=?", (descriptor.workspace_id,)).fetchone()
            if row is None:
                self.store.db.execute("INSERT INTO execution_workspaces VALUES(?,?,?,?,?,'AVAILABLE',NULL,NULL)",
                                      (descriptor.workspace_id, str(descriptor.root), descriptor.physical_id,
                                       descriptor.target_project, descriptor.kind))
            elif (row["root"], row["physical_id"], row["target_project"], row["kind"]) != (
                    str(descriptor.root), descriptor.physical_id, descriptor.target_project, descriptor.kind):
                self.store.db.execute("UPDATE execution_workspaces SET state='INTEGRITY_BLOCKED',last_error='AUTHORITY_REBIND' WHERE workspace_id=?", (descriptor.workspace_id,))
                self.workspaces.block(descriptor.workspace_id)

    def _fresh_now(self) -> float:
        return self.store.now(self._clock())

    def issue_grant(self, *, task_id: str, worker_id: str, session_id: str, lease_id: str,
                    workspace_id: str, allowed_operations: Iterable[str], path_prefixes: Iterable[str] = ("",),
                    grant_seconds: float = 30.0, now: float | None = None) -> dict[str, object]:
        n = self.store.now(now)
        if isinstance(grant_seconds, bool) or not isinstance(grant_seconds, (int, float)) or not math.isfinite(float(grant_seconds)) or grant_seconds <= 0:
            raise BlockedError("invalid grant duration")
        operations = tuple(sorted(set(allowed_operations)))
        if not operations or not set(operations) <= {"CREATE", "REPLACE", "DELETE"}:
            raise BlockedError("invalid operation authority")
        prefixes = tuple(sorted({_normalized_relative(p) if p else "" for p in path_prefixes}))
        try:
            self.store.db.execute("BEGIN IMMEDIATE")
            task = self.store.db.execute("SELECT * FROM tasks WHERE task_id=?", (task_id,)).fetchone()
            worker = self.store.db.execute("SELECT * FROM workers WHERE worker_id=?", (worker_id,)).fetchone()
            if (not task or not worker or task["state"] != "RUNNING" or task["assigned_worker_id"] != worker_id
                    or task["lease_id"] != lease_id or task["lease_expires_at"] <= n
                    or n - worker["last_heartbeat"] > worker["heartbeat_sla"] or worker["last_heartbeat"] > n + 1
                    or not self.gateway.verified_session_binding(worker_id, session_id, now=n)):
                raise BlockedError("execution authority unavailable")
            workspace = self.workspaces.resolve(workspace_id, task["target_project"])
            if task["capability"] not in json.loads(worker["capabilities"]) or task["target_project"] not in json.loads(worker["targets"]):
                raise BlockedError("capability or target mismatch")
            seed = "|".join((task_id, worker_id, session_id, lease_id, workspace.workspace_id, str(n), uuid.uuid4().hex))
            grant_id = hashlib.sha256(seed.encode()).hexdigest()
            expires = min(float(task["lease_expires_at"]), n + float(grant_seconds))
            self.store.db.execute("INSERT INTO execution_grants VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (grant_id, task_id, worker_id, session_id, lease_id, workspace.workspace_id, task["target_project"],
                 task["capability"], json.dumps(operations), json.dumps(prefixes), n, expires, None, "ISSUED", None))
            self.store.audit(task_id, "EXECUTION_GRANT_ISSUED", n, f"grant={grant_id};workspace={workspace_id}")
            self.store.db.execute("COMMIT")
            return self.grant(grant_id)
        except (BlockedError, IntegrityBlockedError):
            if self.store.db.in_transaction:
                self.store.db.execute("ROLLBACK")
            raise
        except sqlite3.OperationalError as exc:
            if self.store.db.in_transaction:
                self.store.db.execute("ROLLBACK")
            if "locked" in str(exc).lower() or "busy" in str(exc).lower():
                raise BlockedError("store busy") from exc
            raise

    def grant(self, grant_id: str) -> dict[str, object]:
        row = self.store.db.execute("SELECT * FROM execution_grants WHERE grant_id=?", (_safe_id(grant_id, "grant_id"),)).fetchone()
        if row is None or row["state"] not in GRANT_STATES:
            raise IntegrityBlockedError("unknown grant")
        return dict(row)

    def canonical_plan(self, plan: ExecutionPlan) -> tuple[str, tuple[dict[str, object], ...], int]:
        if not isinstance(plan, ExecutionPlan) or not 1 <= len(plan.operations) <= MAX_PLAN_FILES:
            raise BlockedError("invalid plan size")
        normalized: list[dict[str, object]] = []
        seen: set[str] = set()
        total = 0
        for item in plan.operations:
            operation = item.operation if item.operation in {"CREATE", "REPLACE", "DELETE"} else None
            path = _normalized_relative(item.path)
            collision = unicodedata.normalize("NFC", path).casefold()
            if collision in seen:
                raise BlockedError("path normalization collision")
            seen.add(collision)
            pre = "ABSENT" if item.expected_preimage.upper() == "ABSENT" else item.expected_preimage.lower()
            post = "ABSENT" if item.desired_postimage.upper() == "ABSENT" else item.desired_postimage.lower()
            if operation == "CREATE" and pre != "ABSENT":
                raise BlockedError("CREATE requires absent preimage")
            if operation in {"REPLACE", "DELETE"} and not _HEX.fullmatch(pre):
                raise BlockedError("invalid preimage")
            content = item.content
            if operation in {"CREATE", "REPLACE"}:
                if not isinstance(content, bytes):
                    raise BlockedError("content bytes required")
                total += len(content)
                content_sha = _sha(content)
                if not _HEX.fullmatch(post) or post != content_sha:
                    raise BlockedError("postimage digest mismatch")
            else:
                if content is not None or post != "ABSENT":
                    raise BlockedError("DELETE requires absent postimage")
                content_sha = "ABSENT"
            normalized.append({"operation": operation, "path": path, "preimage": pre, "postimage": post, "content_sha256": content_sha, "content": content})
        if total > MAX_PLAN_BYTES:
            raise BlockedError("plan payload too large")
        normalized.sort(key=lambda row: row["path"])
        manifest = "".join(f"{row['path']}|{row['operation']}|{row['preimage']}|{row['postimage']}|{row['content_sha256']}\n" for row in normalized).encode()
        return _sha(manifest), tuple(normalized), total

    def _path(self, workspace: WorkspaceDescriptor, relative: str) -> Path:
        if not self.workspaces.path_allowed(relative):
            raise BlockedError("configured protected path")
        if _physical_id(workspace.root) != workspace.physical_id:
            raise IntegrityBlockedError("workspace physical identity changed")
        current = workspace.root
        parts = PurePosixPath(relative).parts
        for part in parts[:-1]:
            current = current / part
            if current.exists():
                stat = current.lstat()
                if current.is_symlink() or _is_reparse(stat) or not current.is_dir():
                    raise BlockedError("symlink or reparse traversal")
        candidate = workspace.root.joinpath(*parts)
        if candidate.exists():
            stat = candidate.lstat()
            if candidate.is_symlink() or _is_reparse(stat):
                raise BlockedError("symlink or reparse target")
            if candidate.is_file() and stat.st_nlink != 1:
                raise BlockedError("hardlinked target")
        resolved_parent = candidate.parent.resolve(strict=True)
        try:
            resolved_parent.relative_to(workspace.root)
        except ValueError as exc:
            raise BlockedError("workspace escape") from exc
        return candidate

    @staticmethod
    def _actual(path: Path) -> tuple[str, bytes | None]:
        if not path.exists():
            return "ABSENT", None
        stat = path.lstat()
        if not path.is_file() or path.is_symlink() or _is_reparse(stat) or stat.st_nlink != 1:
            raise BlockedError("non-regular target")
        data = path.read_bytes()
        return _sha(data), data

    def _workspace_authority(self, grant: sqlite3.Row, now: float) -> WorkspaceDescriptor:
        try:
            workspace = self.workspaces.resolve(grant["workspace_id"], grant["target_project"])
        except IntegrityBlockedError:
            self._block_workspace(grant["workspace_id"], "LOCAL_AUTHORITY_LOST", now)
            raise
        row = self.store.db.execute("SELECT * FROM execution_workspaces WHERE workspace_id=?", (workspace.workspace_id,)).fetchone()
        if row is None or row["state"] == "INTEGRITY_BLOCKED":
            self.workspaces.block(workspace.workspace_id)
            raise IntegrityBlockedError("workspace durably blocked or unknown")
        current_identity = _physical_id(workspace.root)
        expected = (str(workspace.root), workspace.physical_id, workspace.target_project, workspace.kind)
        actual = (row["root"], row["physical_id"], row["target_project"], row["kind"])
        if actual != expected or current_identity != row["physical_id"]:
            self._block_workspace(workspace.workspace_id, "PHYSICAL_IDENTITY_MISMATCH", now)
            raise IntegrityBlockedError("workspace physical identity mismatch")
        self.store.db.execute("UPDATE execution_workspaces SET last_verified_at=?,last_error=NULL WHERE workspace_id=?", (now, workspace.workspace_id))
        return workspace

    def _block_workspace(self, workspace_id: str, reason: str, now: float) -> None:
        self.store.db.execute("UPDATE execution_workspaces SET state='INTEGRITY_BLOCKED',last_verified_at=?,last_error=? WHERE workspace_id=?",
                              (now, clean(reason), workspace_id))
        self.workspaces.block(workspace_id)

    def _authority(self, grant: sqlite3.Row, now: float) -> None:
        task = self.store.db.execute("SELECT * FROM tasks WHERE task_id=?", (grant["task_id"],)).fetchone()
        worker = self.store.db.execute("SELECT * FROM workers WHERE worker_id=?", (grant["worker_id"],)).fetchone()
        if (not task or not worker or task["state"] != "RUNNING" or task["assigned_worker_id"] != grant["worker_id"]
                or task["lease_id"] != grant["lease_id"] or task["lease_expires_at"] <= now
                or grant["expires_at"] <= now):
            raise BlockedError("grant authority expired")
        if now - worker["last_heartbeat"] > worker["heartbeat_sla"] or worker["last_heartbeat"] > now + 1:
            raise BlockedError("worker stale")
        if not self.gateway.verified_session_binding(grant["worker_id"], grant["session_id"], now=now):
            raise BlockedError("session authority unavailable")

    def _fresh_authority(self, grant_id: str) -> tuple[sqlite3.Row, WorkspaceDescriptor, float]:
        fresh = self._fresh_now()
        grant = self.store.db.execute("SELECT * FROM execution_grants WHERE grant_id=?", (grant_id,)).fetchone()
        if grant is None or grant["state"] != "APPLYING":
            raise BlockedError("applying grant authority lost")
        self._authority(grant, fresh)
        workspace = self._workspace_authority(grant, fresh)
        return grant, workspace, fresh

    def apply(self, plan: ExecutionPlan, *, now: float | None = None,
              before_first_write: Callable[[], None] | None = None,
              after_operation: Callable[[int, Path], None] | None = None,
              before_rollback: Callable[[], None] | None = None) -> dict[str, object]:
        n = self.store.now(now)
        plan_hash, operations, _ = self.canonical_plan(plan)
        backups: list[tuple[Path, bytes | None]] = []
        workspace: WorkspaceDescriptor | None = None
        owns_transaction = False
        try:
            self.store.db.execute("BEGIN IMMEDIATE")
            grant = self.store.db.execute("SELECT * FROM execution_grants WHERE grant_id=?", (plan.grant_id,)).fetchone()
            if grant is None or grant["state"] != "ISSUED":
                raise BlockedError("grant replay or unavailable")
            lease_expiry = self.store.db.execute(
                "SELECT lease_expires_at FROM tasks WHERE task_id=? AND lease_id=?",
                (grant["task_id"], grant["lease_id"]),
            ).fetchone()
            if grant["expires_at"] <= n or lease_expiry is None or lease_expiry[0] <= n:
                self.store.db.execute("UPDATE execution_grants SET state='EXPIRED' WHERE grant_id=? AND state='ISSUED'", (plan.grant_id,))
                self.store.audit(grant["task_id"], "EXECUTION_GRANT_EXPIRED", n, f"grant={plan.grant_id}")
                self.store.db.execute("COMMIT")
                raise BlockedError("grant expired")
            self._authority(grant, n)
            workspace = self._workspace_authority(grant, n)
            active_workspace = self.store.db.execute(
                "SELECT 1 FROM execution_grants WHERE workspace_id=? AND state='APPLYING' AND grant_id<>?",
                (grant["workspace_id"], plan.grant_id),
            ).fetchone()
            if active_workspace is not None:
                raise BlockedError("workspace transaction already applying")
            allowed = set(json.loads(grant["operations"])); prefixes = tuple(json.loads(grant["path_prefixes"]))
            if any(row["operation"] not in allowed or not any(not p or row["path"] == p or row["path"].startswith(p + "/") for p in prefixes) for row in operations):
                raise BlockedError("plan outside grant scope")
            resolved = [(row, self._path(workspace, str(row["path"]))) for row in operations]
            for row, path in resolved:
                actual, _ = self._actual(path)
                if actual != row["preimage"]:
                    raise BlockedError("preimage mismatch")
            metadata = [{k: row[k] for k in ("operation", "path", "preimage", "postimage", "content_sha256")} for row in operations]
            self.store.db.execute("INSERT INTO execution_transactions(grant_id,plan_hash,operations_manifest,state,started_at,finished_at,evidence_sha256,error_code,evidence_envelope) VALUES(?,?,?,?,?,?,?,?,?)",
                (plan.grant_id, plan_hash, json.dumps(metadata, sort_keys=True, separators=(",", ":")), "APPLYING", n, None, None, None, None))
            changed = self.store.db.execute("UPDATE execution_grants SET state='APPLYING',consumed_at=?,plan_hash=? WHERE grant_id=? AND state='ISSUED'", (n, plan_hash, plan.grant_id)).rowcount
            if changed != 1:
                raise BlockedError("grant consume lost")
            self.store.audit(grant["task_id"], "EXECUTION_APPLYING", n, f"grant={plan.grant_id};plan={plan_hash}")
            self.store.db.execute("COMMIT")
            owns_transaction = True
            if before_first_write:
                before_first_write()
            grant, workspace, _ = self._fresh_authority(plan.grant_id)
            for row, path in resolved:
                path = self._path(workspace, str(row["path"]))
                actual, original = self._actual(path)
                if actual != row["preimage"]:
                    raise BlockedError("TOCTOU preimage mismatch")
                backups.append((path, original))
            for index, (row, path) in enumerate(resolved):
                grant, workspace, fresh = self._fresh_authority(plan.grant_id)
                path = self._path(workspace, str(row["path"]))
                actual, _ = self._actual(path)
                if actual != row["preimage"]:
                    raise BlockedError("fresh preimage mismatch")
                if row["operation"] == "DELETE":
                    path.unlink()
                else:
                    temporary = path.parent / f".{path.name}.{plan.grant_id}.af03-tmp"
                    if temporary.exists() or temporary.is_symlink():
                        raise IntegrityBlockedError("temporary path collision")
                    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
                    descriptor = os.open(temporary, flags, 0o600)
                    try:
                        os.write(descriptor, row["content"])
                        os.fsync(descriptor)
                    finally:
                        os.close(descriptor)
                    temp_stat = temporary.lstat()
                    if temporary.is_symlink() or _is_reparse(temp_stat) or temp_stat.st_nlink != 1:
                        temporary.unlink(missing_ok=True)
                        raise IntegrityBlockedError("unsafe temporary file")
                    if row["operation"] == "CREATE":
                        if path.exists():
                            temporary.unlink(missing_ok=True)
                            raise BlockedError("CREATE target appeared")
                        os.link(temporary, path)
                        temporary.unlink()
                    else:
                        current, _ = self._actual(path)
                        if current != row["preimage"]:
                            temporary.unlink(missing_ok=True)
                            raise BlockedError("REPLACE target changed")
                        os.replace(temporary, path)
                actual, _ = self._actual(path)
                if actual != row["postimage"]:
                    raise IntegrityBlockedError("postimage verification failed")
                if after_operation:
                    after_operation(index, path)
            grant, workspace, final_now = self._fresh_authority(plan.grant_id)
            evidence_paths = []
            for row in operations:
                path = self._path(workspace, str(row["path"]))
                actual, _ = self._actual(path)
                if actual != row["postimage"]:
                    raise IntegrityBlockedError("final postimage verification failed")
                evidence_paths.append({"path": row["path"], "before_sha256": row["preimage"], "after_sha256": actual})
            envelope = {"task_id": grant["task_id"], "worker_id": grant["worker_id"],
                        "session_id": grant["session_id"], "lease_id": grant["lease_id"],
                        "grant_id": plan.grant_id, "workspace_id": grant["workspace_id"],
                        "plan_hash": plan_hash, "paths": evidence_paths,
                        "applied_at": final_now, "outcome": "APPLIED"}
            envelope_json = json.dumps(envelope, sort_keys=True, separators=(",", ":"))
            evidence_sha = _sha(envelope_json.encode())
            self.store.db.execute("BEGIN IMMEDIATE")
            grant = self.store.db.execute("SELECT * FROM execution_grants WHERE grant_id=?", (plan.grant_id,)).fetchone()
            self._authority(grant, final_now)
            self._workspace_authority(grant, final_now)
            tx_changed = self.store.db.execute("UPDATE execution_transactions SET state='APPLIED',finished_at=?,evidence_sha256=?,evidence_envelope=? WHERE grant_id=? AND state='APPLYING'", (final_now, evidence_sha, envelope_json, plan.grant_id)).rowcount
            grant_changed = self.store.db.execute("UPDATE execution_grants SET state='APPLIED' WHERE grant_id=? AND state='APPLYING'", (plan.grant_id,)).rowcount
            task_changed = self.store.db.execute("UPDATE tasks SET state='REVIEW_PENDING',evidence_status='RECEIVED',updated_at=? WHERE task_id=? AND state='RUNNING'", (final_now, grant["task_id"])).rowcount
            if (tx_changed, grant_changed, task_changed) != (1, 1, 1):
                raise IntegrityBlockedError("durable completion lost")
            self.store.audit(grant["task_id"], "EXECUTION_APPLIED", final_now, f"grant={plan.grant_id};plan={plan_hash};evidence={evidence_sha}")
            self.store.db.execute("COMMIT")
            self.status = "IDLE"; self.last_error = None
            return self.transaction(plan.grant_id)
        except Exception as exc:
            if self.store.db.in_transaction:
                self.store.db.execute("ROLLBACK")
            self.last_error = clean(type(exc).__name__); self.status = "ERROR"
            if backups and workspace is not None:
                rollback_ok = True
                try:
                    if before_rollback:
                        before_rollback()
                    if _physical_id(workspace.root) != workspace.physical_id:
                        raise IntegrityBlockedError("workspace changed before rollback")
                    for path, original in reversed(backups):
                        path = self._path(workspace, path.relative_to(workspace.root).as_posix())
                        if original is None:
                            if path.exists():
                                path.unlink()
                        else:
                            restore = path.parent / f".{path.name}.{plan.grant_id}.af03-rollback"
                            if restore.exists() or restore.is_symlink():
                                raise IntegrityBlockedError("rollback temporary collision")
                            descriptor = os.open(restore, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o600)
                            try:
                                os.write(descriptor, original); os.fsync(descriptor)
                            finally:
                                os.close(descriptor)
                            if path.exists():
                                self._actual(path)
                            os.replace(restore, path)
                    for path, original in backups:
                        actual, _ = self._actual(path)
                        if actual != ("ABSENT" if original is None else _sha(original)):
                            rollback_ok = False
                except Exception:
                    rollback_ok = False
                state = "FAILED" if rollback_ok else "INTEGRITY_BLOCKED"
                if not rollback_ok:
                    self._block_workspace(workspace.workspace_id, "ROLLBACK_UNPROVABLE", n)
                self._terminalize_failure(plan.grant_id, state, type(exc).__name__, n)
            elif owns_transaction and self._transaction_exists(plan.grant_id):
                self._terminalize_failure(plan.grant_id, "FAILED", type(exc).__name__, n)
            raise

    def _transaction_exists(self, grant_id: str) -> bool:
        return self.store.db.execute("SELECT 1 FROM execution_transactions WHERE grant_id=?", (grant_id,)).fetchone() is not None

    def _terminalize_failure(self, grant_id: str, state: str, code: str, now: float) -> None:
        self.store.db.execute("BEGIN IMMEDIATE")
        self.store.db.execute("UPDATE execution_transactions SET state=?,finished_at=?,error_code=? WHERE grant_id=? AND state='APPLYING'", (state, now, clean(code), grant_id))
        self.store.db.execute("UPDATE execution_grants SET state=? WHERE grant_id=? AND state='APPLYING'", (state, grant_id))
        self.store.db.execute("COMMIT")

    def transaction(self, grant_id: str) -> dict[str, object]:
        row = self.store.db.execute("SELECT * FROM execution_transactions WHERE grant_id=?", (grant_id,)).fetchone()
        if row is None:
            raise BlockedError("unknown transaction")
        return dict(row)

    def recover(self, grant_id: str, *, now: float | None = None) -> str:
        n = self.store.now(now)
        grant = self.grant(grant_id)
        tx = self.transaction(grant_id)
        if grant["state"] != "APPLYING" or tx["state"] != "APPLYING":
            raise BlockedError("transaction not recoverable")
        workspace = self._workspace_authority(grant, n)
        rows = json.loads(tx["operations_manifest"])
        actual = [self._actual(self._path(workspace, row["path"]))[0] for row in rows]
        pre = [row["preimage"] for row in rows]; post = [row["postimage"] for row in rows]
        if actual == pre:
            state = "FAILED"
        elif actual == post:
            state = "APPLIED"
        else:
            state = "INTEGRITY_BLOCKED"; self._block_workspace(workspace.workspace_id, "MIXED_RECOVERY_STATE", n)
        self.store.db.execute("BEGIN IMMEDIATE")
        evidence_sha = None; envelope_json = None
        if state == "APPLIED":
            evidence_paths = [{"path": row["path"], "before_sha256": row["preimage"], "after_sha256": actual[index]} for index, row in enumerate(rows)]
            envelope = {"task_id": grant["task_id"], "worker_id": grant["worker_id"],
                        "session_id": grant["session_id"], "lease_id": grant["lease_id"],
                        "grant_id": grant_id, "workspace_id": grant["workspace_id"],
                        "plan_hash": tx["plan_hash"], "paths": evidence_paths,
                        "applied_at": n, "outcome": "APPLIED"}
            envelope_json = json.dumps(envelope, sort_keys=True, separators=(",", ":"))
            evidence_sha = _sha(envelope_json.encode())
        self.store.db.execute("UPDATE execution_transactions SET state=?,finished_at=?,evidence_sha256=?,evidence_envelope=? WHERE grant_id=? AND state='APPLYING'", (state, n, evidence_sha, envelope_json, grant_id))
        self.store.db.execute("UPDATE execution_grants SET state=? WHERE grant_id=? AND state='APPLYING'", (state, grant_id))
        if state == "APPLIED":
            changed = self.store.db.execute("UPDATE tasks SET state='REVIEW_PENDING',evidence_status='RECEIVED',updated_at=? WHERE task_id=? AND state='RUNNING'", (n, grant["task_id"])).rowcount
            if changed != 1:
                self.store.db.execute("ROLLBACK")
                self._block_workspace(workspace.workspace_id, "RECOVERY_REVIEW_TRANSITION_LOST", n)
                raise IntegrityBlockedError("recovery review transition lost")
        self.store.audit(grant["task_id"], "EXECUTION_RECOVERED", n, f"grant={grant_id};state={state}")
        self.store.db.execute("COMMIT")
        return state

    def projection(self, *, now: float | None = None) -> dict[str, object]:
        n = self.store.now(now)
        counts = {state: 0 for state in GRANT_STATES}
        for row in self.store.db.execute("SELECT state,count(*) FROM execution_grants GROUP BY state"):
            if row[0] not in GRANT_STATES:
                return {"status": "UNKNOWN", "last_error": "INTEGRITY_BLOCKED", "counts": "UNKNOWN"}
            counts[row[0]] = row[1]
        active = []
        for row in self.store.db.execute("SELECT grant_id,workspace_id,state,expires_at FROM execution_grants WHERE state IN('ISSUED','APPLYING') ORDER BY grant_id"):
            workspace = self.store.db.execute("SELECT state FROM execution_workspaces WHERE workspace_id=?", (row[1],)).fetchone()
            active.append({"grant_id": row[0], "workspace_id": row[1], "state": "EXPIRED" if row[3] <= n else row[2], "expires_at": row[3], "workspace_state": workspace[0] if workspace else "UNKNOWN"})
        last = self.store.db.execute("SELECT grant_id,state,finished_at,evidence_sha256,error_code FROM execution_transactions ORDER BY started_at DESC LIMIT 1").fetchone()
        workspaces = [dict(row) for row in self.store.db.execute("SELECT workspace_id,target_project,kind,state,last_verified_at,last_error FROM execution_workspaces ORDER BY workspace_id")]
        if last and last["state"] not in GRANT_STATES:
            return {"status": "UNKNOWN", "last_error": "INTEGRITY_BLOCKED",
                    "active_grants": [], "last_execution": "UNKNOWN",
                    "workspaces": workspaces, "counts": "UNKNOWN"}
        blocked = any(row["state"] == "INTEGRITY_BLOCKED" for row in workspaces)
        status = "INTEGRITY_BLOCKED" if blocked else "AVAILABLE" if workspaces else "UNKNOWN"
        last_error = (last["error_code"] if last and last["error_code"] else next((row["last_error"] for row in workspaces if row["last_error"]), "UNKNOWN"))
        return {"status": status, "last_error": last_error, "active_grants": active,
                "last_execution": dict(last) if last else "UNKNOWN", "workspaces": workspaces, "counts": counts}
