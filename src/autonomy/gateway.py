"""Transport-neutral AF-02 worker gateway with an in-memory local harness."""
from __future__ import annotations

import hashlib
import math
import re
from dataclasses import dataclass
from threading import RLock

from .protocol import (
    PROTOCOL_VERSION,
    AckEnvelope,
    DispatchEnvelope,
    HeartbeatEnvelope,
    ResultEnvelope,
    SessionHello,
    WorkerProfile,
)
from .store import AutonomyStore, BlockedError, clean

_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
_SHA256 = re.compile(r"[0-9a-fA-F]{64}")


def _identifier(value: object, label: str) -> str:
    if not isinstance(value, str) or not _IDENTIFIER.fullmatch(value):
        raise BlockedError(f"invalid {label}")
    return value


def _version(value: str) -> None:
    if value != PROTOCOL_VERSION:
        raise BlockedError("unsupported protocol")


def _labels(value: object, label: str) -> tuple[str, ...]:
    if not isinstance(value, (tuple, list)) or not value:
        raise BlockedError(f"invalid {label}")
    result = []
    for item in value:
        result.append(_identifier(item, label))
    return tuple(sorted(set(result)))


@dataclass
class _Session:
    profile: WorkerProfile
    session_id: str
    sequence: int
    observed_at: float
    capacity: int
    provider_state: str
    transport_state: str


@dataclass
class _Dispatch:
    envelope: DispatchEnvelope
    acknowledged: bool = False
    ack_observed_at: float | None = None
    result_received: bool = False


class ImmutableLocalEvidenceResolver:
    """Authority-populated in-memory evidence content with immutable identities."""

    def __init__(self):
        self._content: dict[str, bytes | None] = {}
        self._lock = RLock()

    def declare(self, evidence_id: str, content: bytes | None) -> None:
        identity = _identifier(evidence_id, "evidence_id")
        if content is not None and not isinstance(content, bytes):
            raise BlockedError("evidence content must be bytes")
        immutable = None if content is None else bytes(content)
        with self._lock:
            if identity in self._content:
                if self._content[identity] == immutable:
                    return
                raise BlockedError("immutable evidence conflict")
            self._content[identity] = immutable

    def resolve(self, evidence_id: str) -> bytes:
        identity = _identifier(evidence_id, "evidence_id")
        with self._lock:
            if identity not in self._content:
                raise BlockedError("unknown evidence reference")
            content = self._content[identity]
            if content is None:
                raise BlockedError("evidence content unavailable")
            return bytes(content)


class LocalWorkerGateway:
    """Disposable in-process bridge; VERIFIED means local harness truth only.

    It is not cryptographic proof and never represents verification of a real
    Codex, Antigravity, transport, or external provider connection.
    """

    def __init__(
        self,
        store: AutonomyStore,
        profiles: tuple[WorkerProfile, ...],
        *,
        evidence_resolver: ImmutableLocalEvidenceResolver | None = None,
    ):
        self.store = store
        self._evidence_resolver = evidence_resolver or ImmutableLocalEvidenceResolver()
        self._profiles: dict[str, WorkerProfile] = {}
        for profile in profiles:
            worker_id = _identifier(profile.worker_id, "worker_id")
            _identifier(profile.worker_kind, "worker_kind")
            _labels(profile.capabilities, "capability")
            _labels(profile.allowed_targets, "target")
            if worker_id in self._profiles:
                raise BlockedError("duplicate worker profile")
            if (
                isinstance(profile.max_capacity, bool)
                or not isinstance(profile.max_capacity, int)
                or profile.max_capacity < 0
                or isinstance(profile.heartbeat_sla, bool)
                or not isinstance(profile.heartbeat_sla, (int, float))
                or not math.isfinite(float(profile.heartbeat_sla))
                or profile.heartbeat_sla <= 0
            ):
                raise BlockedError("invalid worker profile")
            self._profiles[worker_id] = profile
        self._sessions: dict[str, _Session] = {}
        self._dispatches: dict[str, _Dispatch] = {}
        self._lock = RLock()

    @staticmethod
    def _time(value: object) -> float:
        try:
            result = float(value)
        except (TypeError, ValueError) as exc:
            raise BlockedError("invalid observed_at") from exc
        if not math.isfinite(result) or result < 0:
            raise BlockedError("invalid observed_at")
        return result

    def register(self, hello: SessionHello, *, now: float) -> None:
        """External envelopes cannot assert provider or transport authority."""
        _version(hello.protocol_version)
        raise BlockedError("local harness authority required")

    def register_local_harness(self, hello: SessionHello, *, now: float) -> None:
        """Establish only locally configured in-process harness truth."""
        _version(hello.protocol_version)
        if hello.provider_state != "UNKNOWN" or hello.transport_state != "UNKNOWN":
            raise BlockedError("self-asserted verification prohibited")
        self._register_local_harness(hello, now=now)

    def _register_local_harness(self, hello: SessionHello, *, now: float) -> None:
        n = self.store.now(now)
        worker_id = _identifier(hello.worker_id, "worker_id")
        session_id = _identifier(hello.session_id, "session_id")
        profile = self._profiles.get(worker_id)
        if profile is None:
            raise BlockedError("unknown worker")
        observed = self._time(hello.observed_at)
        if observed > n + 1 or n - observed > profile.heartbeat_sla:
            raise BlockedError("stale or future session")
        if (
            hello.worker_kind != profile.worker_kind
            or _labels(hello.capabilities, "capability")
            != _labels(profile.capabilities, "capability")
            or _labels(hello.allowed_targets, "target")
            != _labels(profile.allowed_targets, "target")
            or isinstance(hello.capacity, bool)
            or not isinstance(hello.capacity, int)
            or not 0 <= hello.capacity <= profile.max_capacity
            or isinstance(hello.heartbeat_sequence, bool)
            or not isinstance(hello.heartbeat_sequence, int)
            or hello.heartbeat_sequence < 0
        ):
            raise BlockedError("worker profile mismatch")
        with self._lock:
            current = self._sessions.get(worker_id)
            if current is not None and current.session_id != session_id:
                if n - current.observed_at <= current.profile.heartbeat_sla:
                    raise BlockedError("active session conflict")
            if current is not None and current.session_id == session_id:
                if (
                    current.sequence == hello.heartbeat_sequence
                    and current.observed_at == observed
                    and current.capacity == hello.capacity
                ):
                    return
                raise BlockedError("session registration replay")
            self.store.register_worker(
                worker_id=worker_id,
                kind=profile.worker_kind,
                capabilities=profile.capabilities,
                targets=profile.allowed_targets,
                heartbeat_sla=profile.heartbeat_sla,
                capacity=hello.capacity,
                now=observed,
            )
            self._sessions[worker_id] = _Session(
                profile,
                session_id,
                hello.heartbeat_sequence,
                observed,
                hello.capacity,
                "VERIFIED_LOCAL_HARNESS",
                "VERIFIED_LOCAL_HARNESS",
            )

    def heartbeat(self, message: HeartbeatEnvelope, *, now: float) -> None:
        _version(message.protocol_version)
        n = self.store.now(now)
        worker_id = _identifier(message.worker_id, "worker_id")
        session_id = _identifier(message.session_id, "session_id")
        observed = self._time(message.observed_at)
        with self._lock:
            session = self._sessions.get(worker_id)
            if session is None or session.session_id != session_id:
                raise BlockedError("unknown session")
            if (
                isinstance(message.sequence, bool)
                or not isinstance(message.sequence, int)
                or message.sequence <= session.sequence
                or observed <= session.observed_at
                or observed > n + 1
                or n - observed > session.profile.heartbeat_sla
            ):
                raise BlockedError("replayed, stale or future heartbeat")
            if (
                isinstance(message.capacity, bool)
                or not isinstance(message.capacity, int)
                or not 0 <= message.capacity <= session.profile.max_capacity
            ):
                raise BlockedError("capacity overclaim")
            self.store.heartbeat_with_capacity(
                worker_id,
                capacity=message.capacity,
                now=n,
                observed_at=observed,
            )
            session.sequence = message.sequence
            session.observed_at = observed
            session.capacity = message.capacity

    def eligible_sessions(
        self, *, capability: str, target_project: str, now: float
    ) -> list[tuple[str, str]]:
        n = self.store.now(now)
        result = []
        with self._lock:
            for worker_id, session in self._sessions.items():
                if (
                    session.provider_state == "VERIFIED_LOCAL_HARNESS"
                    and session.transport_state == "VERIFIED_LOCAL_HARNESS"
                    and session.observed_at <= n + 1
                    and n - session.observed_at <= session.profile.heartbeat_sla
                    and capability in session.profile.capabilities
                    and target_project in session.profile.allowed_targets
                ):
                    status = self.store.worker_status(worker_id, now=n)
                    if status["status"] == "AVAILABLE" and status[
                        "active_lease_count"
                    ] < min(status["capacity"], session.capacity):
                        result.append((worker_id, session.session_id))
        return sorted(result)

    def dispatch(
        self,
        task: dict[str, object],
        lease: dict[str, object],
        *,
        session_id: str,
        now: float,
    ) -> DispatchEnvelope:
        n = self.store.now(now)
        worker_id = _identifier(lease.get("worker_id"), "worker_id")
        task_id = _identifier(lease.get("task_id"), "task_id")
        lease_id = _identifier(lease.get("lease_id"), "lease_id")
        selected_session_id = _identifier(session_id, "session_id")
        with self._lock:
            session = self._sessions.get(worker_id)
            current = self.store.task(task_id)
            if (
                session is None
                or session.session_id != selected_session_id
                or n - session.observed_at > session.profile.heartbeat_sla
                or current["state"] != "LEASED"
                or current["assigned_worker_id"] != worker_id
                or current["lease_id"] != lease_id
                or current["lease_expires_at"] <= n
                or task.get("task_id") != current["task_id"]
                or task.get("capability") != current["capability"]
                or task.get("target_project") != current["target_project"]
                or current["capability"] not in session.profile.capabilities
                or current["target_project"] not in session.profile.allowed_targets
            ):
                raise BlockedError("dispatch authority unavailable")
            raw = f"{task_id}|{worker_id}|{session.session_id}|{lease_id}".encode()
            dispatch_id = hashlib.sha256(raw).hexdigest()
            existing = self._dispatches.get(dispatch_id)
            if existing is not None:
                return existing.envelope
            envelope = DispatchEnvelope(
                dispatch_id,
                task_id,
                worker_id,
                selected_session_id,
                lease_id,
                current["lease_expires_at"],
                current["capability"],
                current["target_project"],
            )
            self.store.audit(
                task_id,
                "DISPATCHED",
                n,
                f"worker={worker_id};session={session.session_id};lease={lease_id}",
            )
            self._dispatches[dispatch_id] = _Dispatch(envelope)
            return envelope

    def acknowledge(self, message: AckEnvelope, *, now: float) -> None:
        _version(message.protocol_version)
        n = self.store.now(now)
        observed = self._time(message.observed_at)
        with self._lock:
            dispatch = self._bound_dispatch(message)
            session = self._sessions.get(message.worker_id)
            current = self.store.task(message.task_id)
            if (
                session is None
                or session.session_id != message.session_id
                or n - session.observed_at > session.profile.heartbeat_sla
                or observed < session.observed_at
                or observed > n + 1
                or current["assigned_worker_id"] != message.worker_id
                or current["lease_id"] != message.lease_id
                or current["lease_expires_at"] <= n
                or current["state"] not in ({"RUNNING"} if dispatch.acknowledged else {"LEASED"})
            ):
                raise BlockedError("ack authority unavailable")
            if dispatch.acknowledged:
                return
            self.store.start_with_ack(
                message.task_id,
                message.worker_id,
                message.lease_id,
                ack_details=f"worker={message.worker_id};session={message.session_id};lease={message.lease_id}",
                now=n,
            )
            dispatch.acknowledged = True
            dispatch.ack_observed_at = observed

    def result(self, message: ResultEnvelope, *, now: float) -> None:
        _version(message.protocol_version)
        n = self.store.now(now)
        observed = self._time(message.observed_at)
        if observed > n + 1:
            raise BlockedError("future result")
        with self._lock:
            dispatch = self._bound_dispatch(message)
            if not dispatch.acknowledged or dispatch.result_received:
                raise BlockedError("result replay or out of order")
            current = self.store.task(message.task_id)
            session = self._sessions.get(message.worker_id)
            if (
                session is None
                or session.session_id != message.session_id
                or n - session.observed_at > session.profile.heartbeat_sla
                or observed < session.observed_at
                or dispatch.ack_observed_at is None
                or observed < dispatch.ack_observed_at
                or current["state"] != "RUNNING"
                or current["assigned_worker_id"] != message.worker_id
                or current["lease_id"] != message.lease_id
                or current["lease_expires_at"] <= n
            ):
                raise BlockedError("result authority lost")
            if message.status == "SUCCEEDED":
                if len(message.evidence) != 1:
                    raise BlockedError("exactly one evidence reference required")
                evidence = message.evidence[0]
                evidence_id = _identifier(evidence.evidence_id, "evidence_id")
                if not isinstance(evidence.sha256, str) or not _SHA256.fullmatch(
                    evidence.sha256
                ):
                    raise BlockedError("invalid evidence sha256")
                evidence_bytes = self._evidence_resolver.resolve(evidence_id)
                calculated_sha256 = hashlib.sha256(evidence_bytes).hexdigest()
                if calculated_sha256 != evidence.sha256:
                    raise BlockedError("evidence digest mismatch")
                self.store.submit_result(
                    message.task_id,
                    message.worker_id,
                    message.lease_id,
                    evidence_id=evidence_id,
                    sha256=evidence.sha256,
                    now=n,
                )
            elif message.status == "FAILED_SAFE":
                if message.evidence:
                    raise BlockedError("failure evidence not accepted")
                self.store.fail_attempt(
                    message.task_id,
                    message.worker_id,
                    message.lease_id,
                    reason="external worker failed safe",
                    error_code="EXTERNAL_FAILED_SAFE",
                    now=n,
                )
            else:
                raise BlockedError("unsupported result status")
            dispatch.result_received = True

    def _bound_dispatch(self, message: object) -> _Dispatch:
        dispatch_id = _identifier(getattr(message, "dispatch_id"), "dispatch_id")
        dispatch = self._dispatches.get(dispatch_id)
        if dispatch is None:
            raise BlockedError("unknown dispatch")
        envelope = dispatch.envelope
        binding = (
            getattr(message, "task_id"),
            getattr(message, "worker_id"),
            getattr(message, "session_id"),
            getattr(message, "lease_id"),
        )
        expected = (
            envelope.task_id,
            envelope.worker_id,
            envelope.session_id,
            envelope.lease_id,
        )
        if binding != expected:
            raise BlockedError("dispatch binding mismatch")
        return dispatch

    def session_projection(self, *, now: float) -> list[dict[str, object]]:
        n = self.store.now(now)
        rows = []
        with self._lock:
            for worker_id, profile in sorted(self._profiles.items()):
                session = self._sessions.get(worker_id)
                if session is None:
                    rows.append(
                        {
                            "worker_id": worker_id,
                            "provider_kind": profile.worker_kind,
                            "status": "UNKNOWN",
                            "session_status": "UNKNOWN",
                            "freshness": "UNKNOWN",
                            "capacity": None,
                            "verification_scope": "UNKNOWN",
                        }
                    )
                    continue
                age = max(0.0, n - session.observed_at)
                fresh = session.observed_at <= n + 1 and age <= profile.heartbeat_sla
                worker = self.store.worker_status(worker_id, now=n)
                effective_capacity = min(worker["capacity"], session.capacity)
                if not fresh:
                    status = "STALE"
                elif effective_capacity <= worker["active_lease_count"]:
                    status = "AT_CAPACITY"
                else:
                    status = "AVAILABLE"
                rows.append(
                    {
                        "worker_id": worker_id,
                        "provider_kind": profile.worker_kind,
                        "status": status,
                        "session_status": "CONNECTED" if fresh else "STALE",
                        "freshness": age,
                        "capacity": session.capacity,
                        "verification_scope": "LOCAL_HARNESS",
                    }
                )
        return rows

    def dispatch_projection(self) -> list[dict[str, object]]:
        with self._lock:
            return [
                {
                    "task_id": item.envelope.task_id,
                    "worker_id": item.envelope.worker_id,
                    "session_id": item.envelope.session_id,
                    "lease_id": item.envelope.lease_id,
                    "acknowledged": item.acknowledged,
                    "result_received": item.result_received,
                }
                for _, item in sorted(self._dispatches.items())
            ]


class DisposableExternalSession:
    """Test harness for a single configured session; it has no external side effects."""

    def __init__(
        self,
        gateway: LocalWorkerGateway,
        profile: WorkerProfile,
        *,
        session_id: str,
    ):
        self.gateway = gateway
        self.profile = profile
        self.session_id = session_id
        self.sequence = 0

    def connect(self, *, now: float, capacity: int | None = None) -> None:
        chosen = self.profile.max_capacity if capacity is None else capacity
        self.gateway.register_local_harness(
            SessionHello(
                self.profile.worker_id,
                self.profile.worker_kind,
                self.profile.capabilities,
                self.profile.allowed_targets,
                self.session_id,
                self.sequence,
                now,
                chosen,
            ),
            now=now,
        )

    def heartbeat(self, *, now: float, capacity: int | None = None) -> None:
        self.sequence += 1
        chosen = self.profile.max_capacity if capacity is None else capacity
        self.gateway.heartbeat(
            HeartbeatEnvelope(
                self.profile.worker_id,
                self.session_id,
                self.sequence,
                now,
                chosen,
            ),
            now=now,
        )
