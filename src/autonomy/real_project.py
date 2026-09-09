"""AF-08 one-shot canary authority for controlled, disposable project fixtures.

This module does not enable general project mutation.  Its production policy is
empty by default and every write requires an externally provisioned authority.
"""
from __future__ import annotations

import base64
import hashlib
import json
import math
import os
import re
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Callable

from config import settings
from src.directive.approval_engine import ApprovalState, DurableApprovalEngine
from src.directive.contracts import DirectiveEnvelope, DirectivePayload, QueuedDirectiveItem, ValidationStatus
from src.directive.executor import PreExecutionRevalidator
from src.directive.watchdog import HealthState, IncidentAuditTrail, WatchdogHealthMonitor

from .execution import FILE_ATTRIBUTE_REPARSE_POINT
from .gateway import LocalWorkerGateway
from .store import AutonomyStore, BlockedError, IntegrityBlockedError, clean

REAL_PROJECT_MUTATION_ENABLED = False
CONTROL_PLANE_EXECUTE_MUTATING_DIRECTIVES = False
AF08_PROTOCOL = "AF08/1"
ACTION = "GOVERNED_CANARY_WRITE"
CAPABILITY = "PROJECT_CANARY_WRITE"
RISK = "CRITICAL"
WORKSPACE_KIND = "REAL_PROJECT_CANARY"
CANARY_PATH = ".control-plane-canary/af08-canary.txt"
MAX_AUTHORITY_BYTES = 16_384
MAX_FILES = 1
MAX_BYTES = 4096
AUTHORITY_FIELDS = frozenset({
    "protocol_version", "authorization_id", "directive_id", "task_id", "capability",
    "target_project", "project_identity", "pinned_base_commit_sha", "worktree_root",
    "allowed_relative_path", "allowed_operation", "max_files", "max_bytes",
    "expected_preimage_sha256", "expected_postimage_sha256", "approval_receipt_id",
    "issued_at", "expires_at", "nonce", "worker_id", "session_id", "lease_id", "dispatch_id",
})
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
_SHA = re.compile(r"[0-9a-f]{64}")
_GIT_SHA = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})")
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_json(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def _identifier(value: object, label: str) -> str:
    if not isinstance(value, str) or not _ID.fullmatch(value):
        raise BlockedError(f"invalid {label}")
    return value


def _digest_or_absent(value: object, label: str) -> str:
    if value == "ABSENT":
        return value
    if not isinstance(value, str) or not _SHA.fullmatch(value):
        raise BlockedError(f"invalid {label}")
    return value


def _finite(value: object, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise BlockedError(f"invalid {label}")
    result = float(value)
    if not math.isfinite(result) or result < 0:
        raise BlockedError(f"invalid {label}")
    return result


def _physical_id(path: Path) -> str:
    stat = path.stat(follow_symlinks=False)
    if path.is_symlink() or int(getattr(stat, "st_file_attributes", 0)) & FILE_ATTRIBUTE_REPARSE_POINT:
        raise IntegrityBlockedError("workspace reparse identity")
    return f"{int(stat.st_dev)}:{int(stat.st_ino)}"


def _git_read(root: Path, *arguments: str) -> str:
    """Fixed, read-only Git identity query; no caller-controlled command surface."""
    if tuple(arguments) not in {("rev-parse", "HEAD"), ("status", "--porcelain=v1", "--untracked-files=all")}:
        raise BlockedError("git query prohibited")
    try:
        result = subprocess.run(
            ["git", "-C", str(root), *arguments], shell=False, check=False,
            capture_output=True, timeout=5, text=True, encoding="utf-8", errors="strict",
        )
    except (OSError, subprocess.SubprocessError, UnicodeError) as exc:
        raise BlockedError("project identity unavailable") from exc
    if result.returncode != 0 or len(result.stdout) > 65_536 or result.stderr:
        raise BlockedError("project identity unverifiable")
    return result.stdout.strip()


@dataclass(frozen=True)
class RealProjectWorkspace:
    workspace_id: str
    root: Path
    target_project: str
    project_identity: str
    pinned_base_commit_sha: str
    physical_id: str
    kind: str = WORKSPACE_KIND


class RealProjectCanaryRegistry:
    """Authority-owned registry.  It never discovers or auto-enrolls projects."""

    def __init__(self, *, control_plane_root: Path | str):
        self.control_plane_root = Path(control_plane_root).resolve(strict=True)
        self._entries: dict[str, RealProjectWorkspace] = {}
        self._blocked: set[str] = set()

    @staticmethod
    def _overlaps(left: Path, right: Path) -> bool:
        try:
            left.relative_to(right)
            return True
        except ValueError:
            try:
                right.relative_to(left)
                return True
            except ValueError:
                return False

    def register_fixture(self, *, workspace_id: str, root: Path | str, target_project: str,
                         project_identity: str, pinned_base_commit_sha: str) -> RealProjectWorkspace:
        identity = _identifier(workspace_id, "workspace_id")
        project = _identifier(target_project, "target_project")
        if project != "ORACLE-AI":
            raise BlockedError("initial certification target prohibited")
        project_id = _identifier(project_identity, "project_identity")
        if not isinstance(pinned_base_commit_sha, str) or not _GIT_SHA.fullmatch(pinned_base_commit_sha):
            raise BlockedError("invalid pinned base")
        requested = Path(root)
        if not requested.is_absolute() or not requested.exists() or not requested.is_dir() or requested.is_symlink():
            raise BlockedError("workspace unavailable")
        resolved = requested.resolve(strict=True)
        if resolved != requested.absolute() or self._overlaps(resolved, self.control_plane_root):
            raise BlockedError("control-plane or rebound workspace prohibited")
        if _git_read(resolved, "rev-parse", "HEAD") != pinned_base_commit_sha:
            raise BlockedError("wrong pinned base")
        if _git_read(resolved, "status", "--porcelain=v1", "--untracked-files=all"):
            raise BlockedError("dirty workspace")
        descriptor = RealProjectWorkspace(identity, resolved, project, project_id,
                                          pinned_base_commit_sha, _physical_id(resolved))
        current = self._entries.get(identity)
        if current is not None and current != descriptor:
            self._blocked.add(identity)
            raise IntegrityBlockedError("workspace authority rebind")
        self._entries[identity] = descriptor
        return descriptor

    def register_recovery_fixture(self, *, workspace_id: str, root: Path | str,
                                  target_project: str, project_identity: str,
                                  pinned_base_commit_sha: str,
                                  expected_physical_id: str) -> RealProjectWorkspace:
        """Re-enroll an explicit authority-owned descriptor with only its canary residue."""
        identity = _identifier(workspace_id, "workspace_id")
        project = _identifier(target_project, "target_project")
        project_id = _identifier(project_identity, "project_identity")
        requested = Path(root)
        if project != "ORACLE-AI" or not requested.is_absolute() or not requested.exists() or requested.is_symlink():
            raise IntegrityBlockedError("recovery workspace unavailable")
        resolved = requested.resolve(strict=True)
        if resolved != requested.absolute() or self._overlaps(resolved, self.control_plane_root):
            raise IntegrityBlockedError("recovery workspace rebound")
        physical = _physical_id(resolved)
        if physical != expected_physical_id or _git_read(resolved, "rev-parse", "HEAD") != pinned_base_commit_sha:
            raise IntegrityBlockedError("recovery workspace identity mismatch")
        dirty = _git_read(resolved, "status", "--porcelain=v1", "--untracked-files=all").splitlines()
        allowed = {f"?? {CANARY_PATH}", "?? .control-plane-canary/"}
        if any(line not in allowed for line in dirty):
            raise IntegrityBlockedError("unexpected recovery workspace residue")
        descriptor = RealProjectWorkspace(identity, resolved, project, project_id,
                                          pinned_base_commit_sha, physical)
        self._entries[identity] = descriptor
        return descriptor

    def resolve(self, workspace_id: str, *, target_project: str, project_identity: str,
                pinned_base_commit_sha: str, require_clean: bool) -> RealProjectWorkspace:
        identity = _identifier(workspace_id, "workspace_id")
        entry = self._entries.get(identity)
        if entry is None or identity in self._blocked:
            raise IntegrityBlockedError("workspace authority unavailable")
        if (entry.target_project, entry.project_identity, entry.pinned_base_commit_sha) != (
                target_project, project_identity, pinned_base_commit_sha):
            raise BlockedError("workspace binding mismatch")
        if (not entry.root.exists() or entry.root.is_symlink() or entry.root.resolve(strict=True) != entry.root
                or _physical_id(entry.root) != entry.physical_id):
            self._blocked.add(identity)
            raise IntegrityBlockedError("workspace physical identity changed")
        if _git_read(entry.root, "rev-parse", "HEAD") != entry.pinned_base_commit_sha:
            raise BlockedError("workspace base changed")
        if require_clean and _git_read(entry.root, "status", "--porcelain=v1", "--untracked-files=all"):
            raise BlockedError("workspace became dirty")
        return entry


@dataclass(frozen=True)
class CanaryPlan:
    operation: str
    relative_path: str
    content: bytes | None


@dataclass(frozen=True)
class MutationSafetyTruth:
    watchdog_health: str
    killswitch_state: str
    watchdog_observed_at: float
    incident_audit_valid: bool
    killswitch_record_valid: bool


class DurableMutationSafetyAuthority:
    """Derives mutation truth from durable state; missing/corrupt never defaults ARMED."""

    def __init__(self, *, killswitch_file: Path | str, incident_audit_file: Path | str,
                 heartbeat_sla: float = 60.0):
        self.killswitch_file = Path(killswitch_file)
        self.incident_audit = IncidentAuditTrail(Path(incident_audit_file))
        self.monitor = WatchdogHealthMonitor(heartbeat_sla)

    def evaluate(self, *, heartbeat_timestamp: float | None, worker_state: str,
                 crypto_valid: bool, governance_valid: bool, now: float | None = None) -> MutationSafetyTruth:
        if not self.killswitch_file.exists() or self.killswitch_file.is_symlink():
            raise BlockedError("killswitch state missing")
        try:
            raw = self.killswitch_file.read_bytes()
            record = json.loads(raw.decode("utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise IntegrityBlockedError("killswitch state corrupt") from exc
        if not isinstance(record, dict) or set(record) != {"killswitch_state", "active_incident_id", "trigger_reason", "root_cause_resolved", "recovery_approved", "last_updated"}:
            raise IntegrityBlockedError("killswitch state malformed")
        audit_valid, _ = self.incident_audit.verify_integrity()
        health, _ = self.monitor.evaluate_health(heartbeat_timestamp, worker_state, audit_valid,
                                                 crypto_valid, governance_valid)
        observed = time.time() if now is None else float(now)
        return MutationSafetyTruth(health.value if isinstance(health, HealthState) else str(health),
                                   str(record["killswitch_state"]), observed, audit_valid, True)


class ScopedPreExecutionAuthority:
    """Preserves canonical provenance checks while granting no global mutation flag."""

    def __init__(self, revalidator: PreExecutionRevalidator):
        self.revalidator = revalidator

    def verify(self, queued: QueuedDirectiveItem, authority: dict[str, object],
               receipt: dict[str, object]) -> dict[str, object]:
        if (not queued.readback_verified or queued.executed or queued.action_type != ACTION
                or queued.directive_id != authority["directive_id"]
                or queued.target_project != authority["target_project"]
                or receipt["task_id"] != authority["task_id"]
                or receipt["receipt_id"] != authority["approval_receipt_id"]):
            raise BlockedError("scoped preexecution binding mismatch")
        if not queued.directive_payload:
            raise BlockedError("scoped preexecution payload missing")
        payload = DirectivePayload.from_dict(queued.directive_payload)
        envelope = DirectiveEnvelope(
            directive_id=queued.directive_id, payload_commit_sha=queued.directive_source_sha,
            payload_blob_sha=queued.directive_blob_sha, payload_sha256=queued.directive_payload_sha256,
            trusted_remote=settings.APPROVED_SOURCE_REPOSITORY,
            trusted_branch=settings.APPROVED_SOURCE_BRANCH, signer_identity=queued.signer_identity,
        )
        snapshot = {"payload_sha256": queued.directive_payload_sha256,
                    "payload_commit_sha": queued.directive_source_sha,
                    "signer_identity": queued.signer_identity}
        ok, reason, metadata = self.revalidator.authenticator.revalidate_before_execution(
            payload, envelope, snapshot, Path(queued.directive_source_path), force_fresh_fetch=True)
        if not ok or not metadata.get("execution_binding_verified"):
            raise BlockedError("scoped preexecution failed: " + clean(reason))
        return metadata


class ScopedCanaryController:
    """Durable approval, one-shot authority and transactional canary controller."""

    def __init__(self, store: AutonomyStore, gateway: LocalWorkerGateway,
                 registry: RealProjectCanaryRegistry, *, approval_engine: DurableApprovalEngine | None = None,
                 safety_authority: DurableMutationSafetyAuthority | None = None,
                 preexecution_authority: ScopedPreExecutionAuthority | None = None,
                 recovery_workspaces: tuple[dict[str, object], ...] = (),
                 clock: Callable[[], float] = time.time):
        self.store = store
        self.gateway = gateway
        self.registry = registry
        self.approval_engine = approval_engine
        self.safety_authority = safety_authority
        self.preexecution_authority = preexecution_authority
        self.clock = clock
        self._init_schema()
        for descriptor in recovery_workspaces:
            self.reconstruct_workspace(descriptor)

    def _init_schema(self) -> None:
        self.store.db.executescript("""
CREATE TABLE IF NOT EXISTS approval_consumption_receipts(
 receipt_id TEXT PRIMARY KEY,approval_request_id TEXT UNIQUE NOT NULL,directive_id TEXT NOT NULL,
 task_id TEXT NOT NULL,capability TEXT NOT NULL,target TEXT NOT NULL,parameter_hash TEXT NOT NULL,
 risk TEXT NOT NULL,approver_id TEXT NOT NULL,approved_at REAL NOT NULL,consumed_at REAL NOT NULL,
 protocol_version TEXT NOT NULL,digest TEXT NOT NULL,state TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS scoped_mutation_authorities(
 authorization_id TEXT PRIMARY KEY,nonce TEXT UNIQUE NOT NULL,payload TEXT NOT NULL,digest TEXT NOT NULL,
 state TEXT NOT NULL,consumed_at REAL);
CREATE TABLE IF NOT EXISTS real_project_transactions(
 authorization_id TEXT PRIMARY KEY,task_id TEXT NOT NULL,state TEXT NOT NULL,operation TEXT NOT NULL,
 relative_path TEXT NOT NULL,preimage TEXT NOT NULL,postimage TEXT NOT NULL,backup_b64 TEXT,
 started_at REAL NOT NULL,finished_at REAL,evidence_json TEXT,evidence_sha256 TEXT,error_code TEXT);
CREATE TABLE IF NOT EXISTS af08_directive_bindings(
 task_id TEXT PRIMARY KEY,queued_json TEXT NOT NULL,queued_sha256 TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS real_project_workspace_bindings(
 workspace_id TEXT PRIMARY KEY,kind TEXT NOT NULL,target_project TEXT NOT NULL,
 project_identity TEXT NOT NULL,canonical_root TEXT NOT NULL,physical_id TEXT NOT NULL,pinned_base_commit_sha TEXT NOT NULL,
 allowed_relative_path TEXT NOT NULL,authority_version TEXT NOT NULL,authority_digest TEXT NOT NULL,
 authorization_id TEXT NOT NULL,task_id TEXT NOT NULL,approval_receipt_id TEXT NOT NULL,
 expected_preimage TEXT NOT NULL,expected_postimage TEXT NOT NULL);
""")

    def reconstruct_workspace(self, configured: dict[str, object]) -> RealProjectWorkspace:
        required = {"workspace_id", "root", "target_project", "project_identity", "pinned_base_commit_sha"}
        if not isinstance(configured, dict) or set(configured) != required:
            raise IntegrityBlockedError("recovery configuration malformed")
        row = self.store.db.execute("SELECT * FROM real_project_workspace_bindings WHERE workspace_id=?",
                                    (configured["workspace_id"],)).fetchone()
        if not row or row["kind"] != WORKSPACE_KIND or row["allowed_relative_path"] != CANARY_PATH:
            raise IntegrityBlockedError("durable workspace binding unavailable")
        authority = self.store.db.execute("SELECT payload,digest FROM scoped_mutation_authorities WHERE authorization_id=?",
                                          (row["authorization_id"],)).fetchone()
        if not authority or authority["digest"] != row["authority_digest"] or sha256(authority["payload"].encode()) != authority["digest"]:
            raise IntegrityBlockedError("durable authority digest mismatch")
        payload = json.loads(authority["payload"])
        comparisons = ((configured["root"], row["canonical_root"]),
                       (configured["target_project"], row["target_project"]),
                       (configured["project_identity"], row["project_identity"]),
                       (configured["pinned_base_commit_sha"], row["pinned_base_commit_sha"]),
                       (payload["task_id"], row["task_id"]),
                       (payload["approval_receipt_id"], row["approval_receipt_id"]),
                       (payload["expected_preimage_sha256"], row["expected_preimage"]),
                       (payload["expected_postimage_sha256"], row["expected_postimage"]))
        if any(str(left) != str(right) for left, right in comparisons):
            raise IntegrityBlockedError("configured workspace contradicts durable binding")
        workspace = self.registry.register_recovery_fixture(
            workspace_id=str(configured["workspace_id"]), root=str(configured["root"]),
            target_project=str(configured["target_project"]), project_identity=str(configured["project_identity"]),
            pinned_base_commit_sha=str(configured["pinned_base_commit_sha"]),
            expected_physical_id=row["physical_id"])
        if workspace.physical_id != row["physical_id"]:
            raise IntegrityBlockedError("reconstructed workspace physical mismatch")
        tx = self.store.db.execute("SELECT * FROM real_project_transactions WHERE authorization_id=?", (row["authorization_id"],)).fetchone()
        if tx and tx["state"] == "APPLIED" and self._actual(self._target(workspace))[0] != row["expected_postimage"]:
            raise IntegrityBlockedError("reconstructed postimage mismatch")
        return workspace

    def bind_queued_directive(self, task_id: str, queued: QueuedDirectiveItem) -> None:
        raw = canonical_json(queued.to_dict())
        try:
            self.store.db.execute("INSERT INTO af08_directive_bindings VALUES(?,?,?)",
                                  (_identifier(task_id, "task_id"), raw.decode("utf-8"), sha256(raw)))
        except Exception as exc:
            raise BlockedError("directive binding replay") from exc

    def _queued(self, task_id: str) -> QueuedDirectiveItem:
        row = self.store.db.execute("SELECT queued_json,queued_sha256 FROM af08_directive_bindings WHERE task_id=?", (task_id,)).fetchone()
        if not row or sha256(row["queued_json"].encode("utf-8")) != row["queued_sha256"]:
            raise IntegrityBlockedError("directive binding unavailable")
        return QueuedDirectiveItem(**json.loads(row["queued_json"]))

    def _durable_safety(self, worker_id: str, now: float) -> MutationSafetyTruth:
        if self.safety_authority is None:
            raise BlockedError("durable safety authority unavailable")
        session = self.store.db.execute("SELECT last_heartbeat,state FROM af05_sessions WHERE worker_id=?", (worker_id,)).fetchone()
        if not session:
            worker = self.store.db.execute("SELECT last_heartbeat FROM workers WHERE worker_id=?", (worker_id,)).fetchone()
            heartbeat, state = (worker[0] if worker else None), "AVAILABLE"
        else:
            heartbeat, state = session["last_heartbeat"], "AVAILABLE" if session["state"] == "AUTHENTICATED" else "UNKNOWN"
        return self.safety_authority.evaluate(heartbeat_timestamp=heartbeat, worker_state=state,
                                              crypto_valid=True, governance_valid=True, now=now)

    def consume_approval(self, *, engine: DurableApprovalEngine, approval_request_id: str,
                         task_id: str, directive_id: str, parameter_hash: str, now: float | None = None,
                         crash_after_consumption: Callable[[], None] | None = None) -> dict[str, object]:
        n = self.store.now(self.clock() if now is None else now)
        task = self.store.task(task_id)
        record = engine.records.get(approval_request_id)
        audit_ok, _ = engine.audit_chain.verify_integrity()
        if (not audit_ok or not record or task["state"] != "WAITING_HUMAN"
                or task["directive_id"] != directive_id or task["capability"] != CAPABILITY
                or task["target_project"] != "ORACLE-AI" or record.get("state") != "APPROVED"
                or record.get("consumed") or record.get("revoked") or n > record.get("expires_at", -1)
                or record.get("directive_id") != directive_id or record.get("capability_id") != CAPABILITY
                or record.get("parameter_hash") != parameter_hash or record.get("target") != "ORACLE-AI"
                or record.get("risk_class") != RISK or not record.get("approver_id")):
            raise BlockedError("approval unavailable or mismatched")
        receipt_id = "RCP-" + sha256(canonical_json([approval_request_id, task_id, directive_id, parameter_hash]))[:32]
        body = {"receipt_id": receipt_id, "approval_request_id": approval_request_id,
                "directive_id": directive_id, "task_id": task_id, "capability": CAPABILITY,
                "target": "ORACLE-AI", "parameter_hash": parameter_hash, "risk": RISK,
                "approver_id": record["approver_id"], "approved_at": record["approval_timestamp"],
                "consumed_at": n, "protocol_version": AF08_PROTOCOL}
        digest = sha256(canonical_json(body))
        try:
            self.store.db.execute("BEGIN IMMEDIATE")
            self.store.db.execute("INSERT INTO approval_consumption_receipts VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (receipt_id, approval_request_id, directive_id, task_id, CAPABILITY, "ORACLE-AI",
                 parameter_hash, RISK, record["approver_id"], record["approval_timestamp"], n,
                 AF08_PROTOCOL, digest, "PENDING"))
            self.store.db.execute("COMMIT")
        except Exception:
            if self.store.db.in_transaction:
                self.store.db.execute("ROLLBACK")
            raise BlockedError("approval receipt replay")
        ok, _ = engine.transition_state(approval_request_id, ApprovalState.CONSUMED, "AF08_APPROVAL_GATE")
        if not ok:
            raise IntegrityBlockedError("approval consumption lost")
        if crash_after_consumption:
            crash_after_consumption()
        self._release_receipt(receipt_id, engine)
        return self.receipt(receipt_id)

    def _release_receipt(self, receipt_id: str, engine: DurableApprovalEngine) -> None:
        row = self.store.db.execute("SELECT * FROM approval_consumption_receipts WHERE receipt_id=?", (receipt_id,)).fetchone()
        record = engine.records.get(row["approval_request_id"]) if row else None
        if not row or row["state"] not in {"PENDING", "READY"} or not record or record.get("state") != "CONSUMED":
            raise IntegrityBlockedError("receipt recovery truth unavailable")
        self.store.db.execute("BEGIN IMMEDIATE")
        changed = self.store.db.execute(
            "UPDATE tasks SET state='QUEUED',requires_human_approval=0,updated_at=? "
            "WHERE task_id=? AND directive_id=? AND capability=? AND target_project=? AND state='WAITING_HUMAN'",
            (row["consumed_at"], row["task_id"], row["directive_id"], row["capability"], row["target"]),
        ).rowcount
        if changed != 1:
            self.store.db.execute("ROLLBACK")
            raise BlockedError("task release replay or mismatch")
        self.store.db.execute("UPDATE approval_consumption_receipts SET state='READY' WHERE receipt_id=? AND state='PENDING'", (receipt_id,))
        self.store.audit(row["task_id"], "HUMAN_APPROVAL_CONSUMED", row["consumed_at"], f"receipt={receipt_id}")
        self.store.db.execute("COMMIT")

    def recover_approval_release(self, *, engine: DurableApprovalEngine, receipt_id: str) -> dict[str, object]:
        self._release_receipt(receipt_id, engine)
        return self.receipt(receipt_id)

    def reconcile_approval_releases(self) -> list[str]:
        """Recover only receipts backed by the explicitly configured durable engine."""
        if self.approval_engine is None:
            return []
        released = []
        for row in self.store.db.execute("SELECT receipt_id FROM approval_consumption_receipts WHERE state='PENDING' ORDER BY receipt_id"):
            self._release_receipt(row[0], self.approval_engine)
            released.append(row[0])
        return released

    def receipt(self, receipt_id: str) -> dict[str, object]:
        row = self.store.db.execute("SELECT * FROM approval_consumption_receipts WHERE receipt_id=?", (_identifier(receipt_id, "receipt_id"),)).fetchone()
        if not row:
            raise BlockedError("unknown receipt")
        body = {key: row[key] for key in ("receipt_id", "approval_request_id", "directive_id", "task_id",
                "capability", "target", "parameter_hash", "risk", "approver_id", "approved_at",
                "consumed_at", "protocol_version")}
        if row["digest"] != sha256(canonical_json(body)) or row["protocol_version"] != AF08_PROTOCOL:
            raise IntegrityBlockedError("receipt integrity failure")
        return dict(row)

    def provision_authority(self, raw: bytes, *, now: float | None = None) -> dict[str, object]:
        n = self.store.now(self.clock() if now is None else now)
        if not isinstance(raw, bytes) or len(raw) > MAX_AUTHORITY_BYTES:
            raise BlockedError("authority oversized")
        try:
            data = json.loads(raw.decode("utf-8"), parse_constant=lambda x: (_ for _ in ()).throw(ValueError(x)))
        except (UnicodeError, ValueError, json.JSONDecodeError) as exc:
            raise BlockedError("authority malformed") from exc
        if not isinstance(data, dict) or set(data) != AUTHORITY_FIELDS or canonical_json(data) != raw:
            raise BlockedError("authority noncanonical or unknown fields")
        for key in ("authorization_id", "directive_id", "task_id", "target_project", "project_identity",
                    "approval_receipt_id", "nonce", "worker_id", "session_id", "lease_id", "dispatch_id"):
            _identifier(data[key], key)
        if data["protocol_version"] != AF08_PROTOCOL or data["capability"] != CAPABILITY:
            raise BlockedError("authority protocol or capability mismatch")
        if data["target_project"] != "ORACLE-AI" or data["allowed_relative_path"] != CANARY_PATH:
            raise BlockedError("authority target or path mismatch")
        path = data["allowed_relative_path"]
        if (_CONTROL.search(path) or PurePosixPath(path).is_absolute() or PureWindowsPath(path).is_absolute()
                or "\\" in path or ".." in PurePosixPath(path).parts or path.startswith(".git/")):
            raise BlockedError("authority path escape")
        if data["allowed_operation"] not in {"CREATE", "REPLACE", "DELETE"}:
            raise BlockedError("authority operation invalid")
        if data["max_files"] != 1 or isinstance(data["max_bytes"], bool) or not isinstance(data["max_bytes"], int) or not 0 <= data["max_bytes"] <= MAX_BYTES:
            raise BlockedError("authority bounds invalid")
        _digest_or_absent(data["expected_preimage_sha256"], "preimage")
        _digest_or_absent(data["expected_postimage_sha256"], "postimage")
        issued = _finite(data["issued_at"], "issued_at"); expires = _finite(data["expires_at"], "expires_at")
        if issued > n + 1 or expires <= n or expires <= issued:
            raise BlockedError("authority expired or future")
        root = Path(data["worktree_root"])
        if not root.is_absolute():
            raise BlockedError("authority root invalid")
        receipt = self.receipt(data["approval_receipt_id"])
        if (receipt["state"] != "READY" or receipt["directive_id"] != data["directive_id"]
                or receipt["task_id"] != data["task_id"] or receipt["capability"] != data["capability"]
                or receipt["target"] != data["target_project"] or receipt["risk"] != RISK):
            raise BlockedError("approval receipt not ready")
        task = self.store.task(data["task_id"])
        if (task["state"] != "RUNNING" or task["assigned_worker_id"] != data["worker_id"]
                or task["lease_id"] != data["lease_id"] or task["lease_expires_at"] <= n):
            raise BlockedError("authority lease binding unavailable")
        self.registry.resolve(data.get("workspace_id", data["authorization_id"]), target_project=data["target_project"],
                              project_identity=data["project_identity"], pinned_base_commit_sha=data["pinned_base_commit_sha"],
                              require_clean=True)
        digest = sha256(raw)
        workspace = self.registry.resolve(data.get("workspace_id", data["authorization_id"]), target_project=data["target_project"],
                              project_identity=data["project_identity"], pinned_base_commit_sha=data["pinned_base_commit_sha"],
                              require_clean=True)
        try:
            self.store.db.execute("BEGIN IMMEDIATE")
            self.store.db.execute("INSERT INTO scoped_mutation_authorities VALUES(?,?,?,?,'ISSUED',NULL)",
                                  (data["authorization_id"], data["nonce"], raw.decode("utf-8"), digest))
            self.store.db.execute("INSERT INTO real_project_workspace_bindings VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (workspace.workspace_id, workspace.kind, workspace.target_project, workspace.project_identity, str(workspace.root),
                 workspace.physical_id, workspace.pinned_base_commit_sha, CANARY_PATH, AF08_PROTOCOL,
                 digest, data["authorization_id"], data["task_id"], data["approval_receipt_id"],
                 data["expected_preimage_sha256"], data["expected_postimage_sha256"]))
            self.store.db.execute("COMMIT")
        except Exception as exc:
            if self.store.db.in_transaction:
                self.store.db.execute("ROLLBACK")
            raise BlockedError("authority id or nonce replay") from exc
        return {**data, "digest": digest, "state": "ISSUED"}

    def _target(self, workspace: RealProjectWorkspace) -> Path:
        target = workspace.root / CANARY_PATH
        current = workspace.root
        for part in PurePosixPath(CANARY_PATH).parts[:-1]:
            current = current / part
            if current.exists():
                stat = current.lstat()
                if current.is_symlink() or int(getattr(stat, "st_file_attributes", 0)) & FILE_ATTRIBUTE_REPARSE_POINT or not current.is_dir():
                    raise BlockedError("unsafe path traversal")
        if target.exists():
            stat = target.lstat()
            if (target.is_symlink() or not target.is_file() or stat.st_nlink != 1
                    or int(getattr(stat, "st_file_attributes", 0)) & FILE_ATTRIBUTE_REPARSE_POINT):
                raise BlockedError("unsafe canary target")
        if target.parent.parent != workspace.root:
            raise BlockedError("canary path rebound")
        return target

    @staticmethod
    def _actual(path: Path) -> tuple[str, bytes | None]:
        if not path.exists():
            return "ABSENT", None
        stat = path.lstat()
        if not path.is_file() or path.is_symlink() or stat.st_nlink != 1:
            raise BlockedError("non-regular canary")
        value = path.read_bytes()
        return sha256(value), value

    def _safety(self, truth: MutationSafetyTruth, now: float) -> None:
        flags = (settings.CONTROL_PLANE_WRITE_PROJECTS, settings.CONTROL_PLANE_RESTART_PROJECTS,
                 settings.CONTROL_PLANE_CHANGE_STRATEGY, settings.CONTROL_PLANE_ENABLE_REAL_MONEY,
                 settings.CONTROL_PLANE_EXECUTE_PROJECT_CODE, settings.CONTROL_PLANE_EXECUTE_MUTATING_DIRECTIVES,
                 REAL_PROJECT_MUTATION_ENABLED, CONTROL_PLANE_EXECUTE_MUTATING_DIRECTIVES)
        if any(item is not False for item in flags):
            raise IntegrityBlockedError("global safety contradiction")
        if not truth.killswitch_record_valid or not truth.incident_audit_valid:
            raise IntegrityBlockedError("safety state corrupt")
        if truth.killswitch_state != "ARMED" or truth.watchdog_health != "HEALTHY":
            raise BlockedError("watchdog or killswitch blocks mutation")
        observed = _finite(truth.watchdog_observed_at, "watchdog timestamp")
        if observed > now + 1 or now - observed > 60:
            raise BlockedError("watchdog stale")

    def apply(self, authorization_id: str, plan: CanaryPlan, *, worker_id: str, session_id: str,
              lease_id: str, dispatch_id: str, provider_state: str, provider_observed_at: float,
              safety: MutationSafetyTruth | None = None, provenance_verifier: Callable[[str], bool] | None = None,
              now: float | None = None, before_write: Callable[[], None] | None = None,
              after_write: Callable[[], None] | None = None) -> dict[str, object]:
        n = self.store.now(self.clock() if now is None else now)
        row = self.store.db.execute("SELECT * FROM scoped_mutation_authorities WHERE authorization_id=?", (authorization_id,)).fetchone()
        if not row or row["state"] != "ISSUED":
            raise BlockedError("authority replay or unavailable")
        authority = json.loads(row["payload"])
        if (worker_id, session_id, lease_id, dispatch_id) != (authority["worker_id"], authority["session_id"], authority["lease_id"], authority["dispatch_id"]):
            raise BlockedError("authority execution binding mismatch")
        task = self.store.task(authority["task_id"])
        receipt = self.receipt(authority["approval_receipt_id"])
        if receipt["state"] != "READY" or receipt["task_id"] != task["task_id"] or receipt["directive_id"] != task["directive_id"]:
            raise BlockedError("approval receipt binding mismatch")
        if (task["state"] != "RUNNING" or task["assigned_worker_id"] != worker_id or task["lease_id"] != lease_id
                or task["lease_expires_at"] <= n or authority["directive_id"] != task["directive_id"]
                or authority["capability"] != task["capability"] or authority["target_project"] != task["target_project"]):
            raise BlockedError("task or lease binding mismatch")
        if not self.gateway.verified_session_binding(worker_id, session_id, now=n):
            raise BlockedError("session stale or unverified")
        dispatches = [item for item in self.gateway.dispatch_projection() if item["dispatch_id"] == dispatch_id]
        if len(dispatches) != 1 or dispatches[0]["task_id"] != task["task_id"] or dispatches[0]["worker_id"] != worker_id or dispatches[0]["session_id"] != session_id or dispatches[0]["lease_id"] != lease_id or dispatches[0]["state"] != "RUNNING":
            raise BlockedError("dispatch binding mismatch")
        if hasattr(self.gateway, "provider_binding"):
            provider_state, provider_observed_at = self.gateway.provider_binding(worker_id, session_id, now=n)
        if provider_state != "PROVIDER_CONNECTED_UNATTESTED" or n - _finite(provider_observed_at, "provider timestamp") > 60 or provider_observed_at > n + 1:
            raise BlockedError("provider unavailable")
        if self.preexecution_authority is not None:
            self.preexecution_authority.verify(self._queued(task["task_id"]), authority, receipt)
        elif provenance_verifier is None or not provenance_verifier(task["directive_id"]):
            raise BlockedError("directive provenance unavailable")
        if self.safety_authority is not None:
            safety = self._durable_safety(worker_id, n)
        if safety is None:
            raise BlockedError("safety authority unavailable")
        self._safety(safety, n)
        workspace = self.registry.resolve(authorization_id, target_project=authority["target_project"],
            project_identity=authority["project_identity"], pinned_base_commit_sha=authority["pinned_base_commit_sha"], require_clean=True)
        if str(workspace.root) != authority["worktree_root"]:
            raise BlockedError("authority worktree mismatch")
        if not isinstance(plan, CanaryPlan) or plan.operation != authority["allowed_operation"] or plan.relative_path != CANARY_PATH:
            raise BlockedError("planner scope expansion")
        if plan.operation in {"CREATE", "REPLACE"}:
            if not isinstance(plan.content, bytes) or len(plan.content) > authority["max_bytes"] or sha256(plan.content) != authority["expected_postimage_sha256"]:
                raise BlockedError("plan content invalid")
        elif plan.content is not None or authority["expected_postimage_sha256"] != "ABSENT":
            raise BlockedError("delete plan invalid")
        target = self._target(workspace)
        preimage, backup = self._actual(target)
        if preimage != authority["expected_preimage_sha256"]:
            raise BlockedError("preimage mismatch")
        backup_b64 = None if backup is None else base64.b64encode(backup).decode("ascii")
        self.store.db.execute("BEGIN IMMEDIATE")
        changed = self.store.db.execute("UPDATE scoped_mutation_authorities SET state='APPLYING',consumed_at=? WHERE authorization_id=? AND state='ISSUED'", (n, authorization_id)).rowcount
        if changed != 1:
            self.store.db.execute("ROLLBACK"); raise BlockedError("authority consumption lost")
        self.store.db.execute("INSERT INTO real_project_transactions VALUES(?,?,?,?,?,?,?,?,?,NULL,NULL,NULL,NULL)",
            (authorization_id, task["task_id"], "APPLYING", plan.operation, CANARY_PATH, preimage,
             authority["expected_postimage_sha256"], backup_b64, n))
        self.store.audit(task["task_id"], "AF08_APPLYING", n, f"authority={authorization_id}")
        self.store.db.execute("COMMIT")
        # The hook models an abrupt process loss after durable intent.  It is
        # deliberately outside rollback handling so restart reconciliation can
        # observe the genuine APPLYING window.
        if before_write:
            before_write()
        try:
            fresh = self.store.now(self.clock())
            task = self.store.task(task["task_id"])
            if task["state"] != "RUNNING" or task["lease_id"] != lease_id or task["lease_expires_at"] <= fresh:
                raise BlockedError("lease lost before write")
            if not self.gateway.verified_session_binding(worker_id, session_id, now=fresh):
                raise BlockedError("fresh authority lost")
            if self.preexecution_authority is not None:
                self.preexecution_authority.verify(self._queued(task["task_id"]), authority, receipt)
            elif provenance_verifier is None or not provenance_verifier(task["directive_id"]):
                raise BlockedError("fresh provenance lost")
            if self.safety_authority is not None:
                safety = self._durable_safety(worker_id, fresh)
            self._safety(safety, fresh)
            workspace = self.registry.resolve(authorization_id, target_project=authority["target_project"], project_identity=authority["project_identity"], pinned_base_commit_sha=authority["pinned_base_commit_sha"], require_clean=True)
            target = self._target(workspace)
            if self._actual(target)[0] != preimage:
                raise BlockedError("TOCTOU preimage mismatch")
            target.parent.mkdir(mode=0o700, exist_ok=True)
            if plan.operation == "DELETE":
                target.unlink()
            else:
                temporary = target.parent / f".{target.name}.{authorization_id}.tmp"
                descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0), 0o600)
                try:
                    os.write(descriptor, plan.content); os.fsync(descriptor)
                finally:
                    os.close(descriptor)
                if plan.operation == "CREATE":
                    os.link(temporary, target); temporary.unlink()
                else:
                    os.replace(temporary, target)
            postimage = self._actual(target)[0]
            if postimage != authority["expected_postimage_sha256"]:
                raise IntegrityBlockedError("postimage mismatch")
            if after_write:
                after_write()
            evidence = {"protocol_version": AF08_PROTOCOL, "authorization_id": authorization_id,
                "approval_receipt_id": receipt["receipt_id"], "directive_id": task["directive_id"],
                "task_id": task["task_id"], "worker_id": worker_id, "session_id": session_id,
                "lease_id": lease_id, "dispatch_id": dispatch_id, "workspace_id": workspace.workspace_id,
                "project_identity": workspace.project_identity, "pinned_base_commit_sha": workspace.pinned_base_commit_sha,
                "relative_path": CANARY_PATH, "operation": plan.operation, "preimage_sha256": preimage,
                "postimage_sha256": postimage, "observed_at": fresh, "outcome": "REVIEW_PENDING"}
            evidence_json = canonical_json(evidence).decode("utf-8")
            self.store.db.execute("BEGIN IMMEDIATE")
            self.store.db.execute("UPDATE real_project_transactions SET state='APPLIED',finished_at=?,evidence_json=?,evidence_sha256=? WHERE authorization_id=? AND state='APPLYING'", (fresh, evidence_json, sha256(evidence_json.encode()), authorization_id))
            self.store.db.execute("UPDATE scoped_mutation_authorities SET state='CONSUMED' WHERE authorization_id=? AND state='APPLYING'", (authorization_id,))
            changed = self.store.db.execute("UPDATE tasks SET state='REVIEW_PENDING',evidence_status='RECEIVED',updated_at=? WHERE task_id=? AND state='RUNNING' AND lease_id=?", (fresh, task["task_id"], lease_id)).rowcount
            if changed != 1:
                raise IntegrityBlockedError("review transition lost")
            self.store.audit(task["task_id"], "AF08_APPLIED", fresh, f"authority={authorization_id};evidence={sha256(evidence_json.encode())}")
            self.store.db.execute("COMMIT")
            return {**evidence, "evidence_sha256": sha256(evidence_json.encode())}
        except BaseException as exc:
            if isinstance(exc, (SystemExit, KeyboardInterrupt)):
                raise
            if self.store.db.in_transaction:
                self.store.db.execute("ROLLBACK")
            try:
                self._restore(target, backup, authorization_id)
                state = "FAILED"
            except Exception:
                state = "INTEGRITY_BLOCKED"
            self.store.db.execute("UPDATE real_project_transactions SET state=?,finished_at=?,error_code=? WHERE authorization_id=? AND state='APPLYING'", (state, self.store.now(self.clock()), clean(type(exc).__name__), authorization_id))
            self.store.db.execute("UPDATE scoped_mutation_authorities SET state=? WHERE authorization_id=? AND state='APPLYING'", (state, authorization_id))
            raise

    def _restore(self, target: Path, backup: bytes | None, authorization_id: str) -> None:
        if backup is None:
            if target.exists():
                target.unlink()
            return
        restore = target.parent / f".{target.name}.{authorization_id}.rollback"
        restore.write_bytes(backup)
        os.replace(restore, target)
        if self._actual(target)[0] != sha256(backup):
            raise IntegrityBlockedError("rollback verification failed")

    def rollback(self, authorization_id: str) -> None:
        tx = self.store.db.execute("SELECT * FROM real_project_transactions WHERE authorization_id=?", (authorization_id,)).fetchone()
        if not tx or tx["state"] != "APPLIED":
            raise BlockedError("transaction not rollbackable")
        authority = json.loads(self.store.db.execute("SELECT payload FROM scoped_mutation_authorities WHERE authorization_id=?", (authorization_id,)).fetchone()[0])
        workspace = self.registry.resolve(authorization_id, target_project=authority["target_project"], project_identity=authority["project_identity"], pinned_base_commit_sha=authority["pinned_base_commit_sha"], require_clean=False)
        target = self._target(workspace)
        backup = None if tx["backup_b64"] is None else base64.b64decode(tx["backup_b64"], validate=True)
        self._restore(target, backup, authorization_id)
        self.store.db.execute("UPDATE real_project_transactions SET state='ROLLED_BACK' WHERE authorization_id=?", (authorization_id,))

    def recover_applying(self, authorization_id: str) -> str:
        tx = self.store.db.execute("SELECT * FROM real_project_transactions WHERE authorization_id=?", (authorization_id,)).fetchone()
        if not tx or tx["state"] != "APPLYING":
            raise BlockedError("transaction not recoverable")
        authority = json.loads(self.store.db.execute("SELECT payload FROM scoped_mutation_authorities WHERE authorization_id=?", (authorization_id,)).fetchone()[0])
        workspace = self.registry.resolve(authorization_id, target_project=authority["target_project"], project_identity=authority["project_identity"], pinned_base_commit_sha=authority["pinned_base_commit_sha"], require_clean=False)
        target = self._target(workspace)
        backup = None if tx["backup_b64"] is None else base64.b64decode(tx["backup_b64"], validate=True)
        self._restore(target, backup, authorization_id)
        self.store.db.execute("UPDATE real_project_transactions SET state='FAILED',finished_at=?,error_code='RECOVERED_ROLLBACK' WHERE authorization_id=? AND state='APPLYING'", (self.store.now(self.clock()), authorization_id))
        self.store.db.execute("UPDATE scoped_mutation_authorities SET state='FAILED' WHERE authorization_id=? AND state='APPLYING'", (authorization_id,))
        return "FAILED"


class AF08ProductProcessor:
    """Runtime hook that advances only already-issued, fully bound authorities."""

    def __init__(self, controller: ScopedCanaryController, planner):
        self.controller = controller
        self.planner = planner

    def process_ready(self, *, now: float) -> list[str]:
        completed: list[str] = []
        rows = self.controller.store.db.execute(
            "SELECT authorization_id,payload FROM scoped_mutation_authorities WHERE state='ISSUED' ORDER BY authorization_id"
        ).fetchall()
        for row in rows:
            authority = json.loads(row["payload"])
            dispatches = [item for item in self.controller.gateway.dispatch_projection()
                          if item.get("dispatch_id") == authority["dispatch_id"]]
            if len(dispatches) != 1 or dispatches[0].get("state") != "RUNNING":
                raise BlockedError("runtime dispatch binding unavailable")
            from .protocol import DispatchEnvelope
            dispatch = DispatchEnvelope(
                authority["dispatch_id"], authority["task_id"], authority["worker_id"],
                authority["session_id"], authority["lease_id"],
                float(dispatches[0]["lease_expires_at"]), authority["capability"],
                authority["target_project"], str(dispatches[0]["protocol"]),
            )
            plan = self.planner.plan(dispatch, authority)
            provider_state, provider_at = self.controller.gateway.provider_binding(
                authority["worker_id"], authority["session_id"], now=now)
            self.controller.apply(
                authority["authorization_id"], plan, worker_id=authority["worker_id"],
                session_id=authority["session_id"], lease_id=authority["lease_id"],
                dispatch_id=authority["dispatch_id"], provider_state=provider_state,
                provider_observed_at=provider_at, now=now,
            )
            completed.append(authority["authorization_id"])
        return completed


assert REAL_PROJECT_MUTATION_ENABLED is False
assert CONTROL_PLANE_EXECUTE_MUTATING_DIRECTIVES is False
