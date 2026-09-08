"""AF-07 separately hosted, fail-closed autonomy service lifecycle."""
from __future__ import annotations

import argparse
import json
import math
import os
import re
import signal
import sqlite3
import sys
import threading
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from config import settings
from src.directive.authenticator import DirectiveAuthenticator

from .protocol import REAL_PROJECT_MUTATION_ENABLED
from .runtime import AutonomyRuntime, RuntimeRootPolicy
from .store import BlockedError, IntegrityBlockedError, clean

SERVICE_PROTOCOL_VERSION = "AF07/1"
CONFIG_SCHEMA_VERSION = 1
MAX_CONFIG_BYTES = 65536
SERVICE_STATES = frozenset({"STARTING", "RUNNING", "IDLE", "BACKOFF", "BLOCKED", "INTEGRITY_BLOCKED", "STOPPING", "STOPPED", "CRASHED"})
ACTIVE_STATES = frozenset({"STARTING", "RUNNING", "IDLE", "BACKOFF", "STOPPING"})
IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
SECRET_KEY = re.compile(r"(?i)(secret|token|password|api[_-]?key|credential|authorization)")
EXPECTED_CONFIG_KEYS = frozenset({
    "schema_version", "service_id", "runtime_root", "queue_path", "repository_roots",
    "supported_targets", "cadence_seconds", "backoff_initial_seconds",
    "backoff_max_seconds", "backoff_multiplier", "max_consecutive_transient_failures",
    "health_stale_seconds",
})


def _number(value: object, label: str, minimum: float, maximum: float) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise BlockedError(f"invalid {label}")
    result = float(value)
    if not math.isfinite(result) or not minimum <= result <= maximum:
        raise BlockedError(f"invalid {label}")
    return result


def _real_file(value: object, label: str) -> Path:
    if not isinstance(value, str) or not Path(value).is_absolute():
        raise BlockedError(f"invalid {label}")
    path = Path(value)
    try:
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise BlockedError(f"{label} unavailable") from exc
    if path.is_symlink() or not resolved.is_file() or os.path.normcase(str(path.absolute())) != os.path.normcase(str(resolved)):
        raise BlockedError(f"unsafe {label}")
    attributes = int(getattr(resolved.stat(follow_symlinks=False), "st_file_attributes", 0))
    if attributes & 0x400:
        raise BlockedError(f"reparse {label}")
    return resolved


@dataclass(frozen=True)
class ServiceConfig:
    service_id: str
    runtime_root: Path
    queue_path: Path
    repository_roots: tuple[Path, ...]
    supported_targets: tuple[str, ...]
    cadence_seconds: float
    backoff_initial_seconds: float
    backoff_max_seconds: float
    backoff_multiplier: float
    max_consecutive_transient_failures: int
    health_stale_seconds: float

    @classmethod
    def load(cls, path: Path | str) -> "ServiceConfig":
        config_path = _real_file(str(path), "config path")
        raw = config_path.read_bytes()
        if len(raw) > MAX_CONFIG_BYTES:
            raise BlockedError("config oversized")
        try:
            data = json.loads(raw.decode("utf-8"), parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)))
        except (UnicodeError, json.JSONDecodeError, ValueError) as exc:
            raise BlockedError("config malformed") from exc
        if not isinstance(data, dict) or set(data) != EXPECTED_CONFIG_KEYS:
            raise BlockedError("config schema mismatch")
        if any(SECRET_KEY.search(str(key)) for key in data):
            raise BlockedError("secret field prohibited")
        if isinstance(data["schema_version"], bool) or data["schema_version"] != CONFIG_SCHEMA_VERSION:
            raise BlockedError("unsupported config version")
        service_id = data["service_id"]
        if not isinstance(service_id, str) or not IDENTIFIER.fullmatch(service_id):
            raise BlockedError("invalid service identity")
        roots_value = data["repository_roots"]
        if not isinstance(roots_value, list) or not roots_value:
            raise BlockedError("repository roots required")
        roots = []
        for value in roots_value:
            if not isinstance(value, str) or not Path(value).is_absolute():
                raise BlockedError("invalid repository root")
            try:
                resolved = Path(value).resolve(strict=True)
            except OSError as exc:
                raise BlockedError("repository root unavailable") from exc
            if not resolved.is_dir() or Path(value).is_symlink():
                raise BlockedError("unsafe repository root")
            roots.append(resolved)
        runtime_value = data["runtime_root"]
        if not isinstance(runtime_value, str) or not Path(runtime_value).is_absolute():
            raise BlockedError("invalid runtime root")
        service_repository = Path(__file__).resolve().parents[2]
        runtime_root = RuntimeRootPolicy((*roots, service_repository)).validate(runtime_value)
        queue_path = _real_file(data["queue_path"], "queue path")
        targets_value = data["supported_targets"]
        if not isinstance(targets_value, list) or not targets_value or any(not isinstance(item, str) for item in targets_value):
            raise BlockedError("supported targets required")
        targets = tuple(sorted(set(targets_value)))
        if any(target not in settings.REGISTERED_PROJECTS for target in targets):
            raise BlockedError("unknown target")
        max_failures = data["max_consecutive_transient_failures"]
        if isinstance(max_failures, bool) or not isinstance(max_failures, int) or not 1 <= max_failures <= 100:
            raise BlockedError("invalid transient failure bound")
        initial = _number(data["backoff_initial_seconds"], "initial backoff", 0.01, 300)
        maximum = _number(data["backoff_max_seconds"], "maximum backoff", initial, 3600)
        return cls(
            service_id, runtime_root, queue_path, tuple(roots), targets,
            _number(data["cadence_seconds"], "cadence", 0.01, 3600), initial, maximum,
            _number(data["backoff_multiplier"], "backoff multiplier", 1, 10), max_failures,
            _number(data["health_stale_seconds"], "health stale threshold", 1, 86400),
        )


class CanonicalProvenanceVerifier:
    """Thin production adapter; all authority remains in DirectiveAuthenticator."""

    def __init__(self, repository_root: Path | str):
        self.authenticator = DirectiveAuthenticator(repo_root=Path(repository_root))

    def __call__(self, payload, envelope, directive_file_path=None):
        return self.authenticator.authenticate(payload, envelope, directive_file_path)


class ServiceInstanceLock:
    """Held kernel lock; file presence alone never proves ownership."""

    def __init__(self, runtime_root: Path):
        self.path = runtime_root / "af07.service.lock"
        self.metadata_path = runtime_root / "af07.service.owner.json"
        self.handle = None

    def acquire(self, *, service_id: str, instance_id: str) -> bool:
        try:
            flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
            descriptor = os.open(self.path, flags, 0o600)
            opened = os.fstat(descriptor)
            physical = self.path.lstat()
            if (self.path.is_symlink() or int(getattr(physical, "st_file_attributes", 0)) & 0x400
                    or opened.st_nlink != 1 or (opened.st_dev, opened.st_ino) != (physical.st_dev, physical.st_ino)):
                os.close(descriptor)
                return False
            self.handle = os.fdopen(descriptor, "r+b")
        except OSError:
            self.handle = None
            return False
        try:
            self.handle.seek(0)
            if self.handle.read(1) == b"":
                self.handle.write(b"\0")
                self.handle.flush()
            self.handle.seek(0)
        except OSError:
            self.handle.close()
            self.handle = None
            return False
        try:
            if os.name == "nt":
                import msvcrt
                msvcrt.locking(self.handle.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(self.handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except (OSError, BlockingIOError):
            self.handle.close()
            self.handle = None
            return False
        metadata = json.dumps({"service_id": service_id, "instance_id": instance_id, "pid": os.getpid()}, sort_keys=True).encode()
        temporary = self.metadata_path.with_name(f".{self.metadata_path.name}.{instance_id}.tmp")
        try:
            descriptor = os.open(
                temporary,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0),
                0o600,
            )
            try:
                os.write(descriptor, metadata)
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            os.replace(temporary, self.metadata_path)
        except OSError:
            temporary.unlink(missing_ok=True)
            self.release()
            return False
        return True

    def release(self) -> None:
        if self.handle is None:
            return
        try:
            self.handle.seek(0)
            if os.name == "nt":
                import msvcrt
                msvcrt.locking(self.handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl
                fcntl.flock(self.handle.fileno(), fcntl.LOCK_UN)
        finally:
            self.handle.close()
            self.handle = None


class AutonomyServiceHost:
    """Owns only its AF-07 runtime and invokes only AutonomyRuntime.run_once()."""

    def __init__(self, config: ServiceConfig, *, runtime_factory=AutonomyRuntime,
                 verifier=None, clock: Callable[[], float] = time.time,
                 stop_event: threading.Event | None = None):
        self.config = config
        self.clock = clock
        self.stop_event = stop_event or threading.Event()
        self.instance_id = str(uuid.uuid4())
        self.lock = ServiceInstanceLock(config.runtime_root)
        self.runtime_factory = runtime_factory
        self.verifier = verifier or CanonicalProvenanceVerifier(Path(__file__).resolve().parents[2])
        self.runtime = None

    def _init_health(self) -> None:
        self.runtime.store.db.executescript("""
CREATE TABLE IF NOT EXISTS af07_service_health(
 service_id TEXT PRIMARY KEY,service_protocol_version TEXT NOT NULL,instance_id TEXT NOT NULL,
 status TEXT NOT NULL,started_at REAL NOT NULL,heartbeat_at REAL NOT NULL,cycle_count INTEGER NOT NULL,
 consecutive_failures INTEGER NOT NULL,last_error_class TEXT,next_retry_at REAL,last_stop_reason TEXT,
 previous_instance_state TEXT,recovery_observed INTEGER NOT NULL);
""")

    def _health(self, status: str, *, failures: int = 0, retry_at: float | None = None,
                error: str | None = None, reason: str | None = None, increment: bool = False) -> None:
        if status not in SERVICE_STATES:
            raise IntegrityBlockedError("invalid service state")
        now = float(self.clock())
        previous = self.runtime.store.db.execute(
            "SELECT status,cycle_count FROM af07_service_health WHERE service_id=?", (self.config.service_id,)
        ).fetchone()
        cycle_count = (previous[1] if previous else 0) + int(increment)
        started = now
        old_state = previous[0] if previous else None
        if previous and status != "STARTING":
            row = self.runtime.store.db.execute("SELECT started_at FROM af07_service_health WHERE service_id=?", (self.config.service_id,)).fetchone()
            started = row[0]
        self.runtime.store.db.execute(
            "INSERT OR REPLACE INTO af07_service_health VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (self.config.service_id, SERVICE_PROTOCOL_VERSION, self.instance_id, status, started, now,
             cycle_count, failures, clean(error) if error else None, retry_at, clean(reason) if reason else None,
             old_state, int(bool(previous))),
        )

    @staticmethod
    def _transient(exc: BaseException) -> bool:
        return isinstance(exc, (TimeoutError, sqlite3.OperationalError)) and (
            isinstance(exc, TimeoutError) or any(word in str(exc).lower() for word in ("locked", "busy", "temporarily"))
        )

    def run(self, *, cycles: int | None = None) -> int:
        if cycles is not None and (isinstance(cycles, bool) or not isinstance(cycles, int) or not 1 <= cycles <= 10000):
            raise BlockedError("invalid service cycle bound")
        if not self.lock.acquire(service_id=self.config.service_id, instance_id=self.instance_id):
            raise BlockedError("SERVICE_START=BLOCKED_SINGLE_INSTANCE")
        failures = 0
        completed = 0
        try:
            try:
                self.runtime = self.runtime_factory(
                    runtime_root=self.config.runtime_root, queue_path=self.config.queue_path,
                    repository_roots=self.config.repository_roots, supported_targets=self.config.supported_targets,
                    verifier=self.verifier,
                )
                integrity = self.runtime.store.db.execute("PRAGMA integrity_check").fetchone()
                if integrity is None or integrity[0] != "ok":
                    raise IntegrityBlockedError("runtime store integrity blocked")
                self._init_health()
            except sqlite3.DatabaseError as exc:
                raise IntegrityBlockedError("runtime store integrity unavailable") from exc
            self._health("STARTING")
            while not self.stop_event.is_set():
                try:
                    self._health("RUNNING", failures=failures)
                    self.runtime.run_once()
                    failures = 0
                    completed += 1
                    self._health("IDLE", increment=True)
                    if cycles is not None and completed >= cycles:
                        break
                    self.stop_event.wait(self.config.cadence_seconds)
                except IntegrityBlockedError as exc:
                    self._health("INTEGRITY_BLOCKED", error=type(exc).__name__, reason="INTEGRITY_BLOCKED")
                    return 4
                except BlockedError as exc:
                    self._health("BLOCKED", error=type(exc).__name__, reason="BLOCKED")
                    return 3
                except Exception as exc:
                    if not self._transient(exc):
                        self._health("CRASHED", error=type(exc).__name__, reason="FATAL")
                        return 5
                    failures += 1
                    if failures > self.config.max_consecutive_transient_failures:
                        self._health("CRASHED", failures=failures, error=type(exc).__name__, reason="TRANSIENT_LIMIT")
                        return 5
                    delay = min(self.config.backoff_initial_seconds * self.config.backoff_multiplier ** (failures - 1), self.config.backoff_max_seconds)
                    self._health("BACKOFF", failures=failures, retry_at=float(self.clock()) + delay, error=type(exc).__name__)
                    self.stop_event.wait(delay)
            self._health("STOPPING", reason="GRACEFUL")
            self._health("STOPPED", reason="GRACEFUL")
            return 0
        finally:
            if self.runtime is not None:
                self.runtime.store.close()
            self.lock.release()


def read_status(config: ServiceConfig, *, now: float | None = None) -> dict[str, object]:
    database = config.runtime_root / "autonomy.sqlite"
    if not database.is_file():
        return {"service_id": config.service_id, "status": "UNKNOWN", "freshness": "UNKNOWN"}
    connection = sqlite3.connect(f"file:{database.as_posix()}?mode=ro", uri=True)
    connection.row_factory = sqlite3.Row
    try:
        row = connection.execute("SELECT * FROM af07_service_health WHERE service_id=?", (config.service_id,)).fetchone()
    except sqlite3.DatabaseError:
        return {"service_id": config.service_id, "status": "INTEGRITY_BLOCKED", "freshness": "UNKNOWN"}
    finally:
        connection.close()
    if row is None:
        return {"service_id": config.service_id, "status": "UNKNOWN", "freshness": "UNKNOWN"}
    result = dict(row)
    current = time.time() if now is None else float(now)
    stale = current - result["heartbeat_at"] > config.health_stale_seconds or result["heartbeat_at"] > current + 1
    result["freshness"] = "STALE" if stale else "FRESH"
    if stale and result["status"] in ACTIVE_STATES:
        result["status"] = "CRASH_SUSPECTED"
    return result


def _safety() -> None:
    values = (
        settings.CONTROL_PLANE_RESTART_PROJECTS, settings.CONTROL_PLANE_EXECUTE_PROJECT_CODE,
        settings.CONTROL_PLANE_EXECUTE_MUTATING_DIRECTIVES, settings.CONTROL_PLANE_WRITE_PROJECTS,
        settings.CONTROL_PLANE_CHANGE_STRATEGY, settings.CONTROL_PLANE_ENABLE_REAL_MONEY,
        REAL_PROJECT_MUTATION_ENABLED,
    )
    if any(value is not False for value in values):
        raise BlockedError("hard safety invariant violated")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="AF-07 autonomy service")
    parser.add_argument("--config", required=True)
    parser.add_argument("--status", action="store_true")
    parser.add_argument("--cycles", type=int)
    args = parser.parse_args(argv)
    try:
        _safety()
        config = ServiceConfig.load(args.config)
        if args.status:
            print(json.dumps(read_status(config), sort_keys=True))
            return 0
        host = AutonomyServiceHost(config)
        signal.signal(signal.SIGINT, lambda *_: host.stop_event.set())
        if hasattr(signal, "SIGTERM"):
            signal.signal(signal.SIGTERM, lambda *_: host.stop_event.set())
        return host.run(cycles=args.cycles)
    except IntegrityBlockedError:
        print(json.dumps({"status": "INTEGRITY_BLOCKED"}, sort_keys=True))
        return 4
    except BlockedError as exc:
        print(json.dumps({"status": "BLOCKED", "reason": clean(str(exc))}, sort_keys=True))
        return 3


if __name__ == "__main__":
    raise SystemExit(main())


assert REAL_PROJECT_MUTATION_ENABLED is False
