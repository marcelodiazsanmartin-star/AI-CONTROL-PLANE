"""AF-06 provider-bound read-only execution over the AF-05 authenticated bridge."""
from __future__ import annotations

import base64
import hashlib
import json
import math
import os
import re
import sqlite3
import ssl
from dataclasses import asdict, dataclass
from typing import Callable, Protocol
from urllib import error as urlerror
from urllib import request as urlrequest

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .external_gateway import AF05_PROTOCOL_VERSION, DOMAINS, AuthenticatedExternalGateway
from .protocol import DispatchEnvelope, REAL_PROJECT_MUTATION_ENABLED
from .store import BlockedError, clean
from .trust import ALLOWED_CAPABILITIES, TrustedWorkerProfile, canonical_json, signed_bytes

AF06_PROTOCOL_VERSION = "AF06/1"
PROVIDER_KIND = "OPENAI_RESPONSES"
CODEX_CLI_PROVIDER_KIND = "CODEX_CLI_CHATGPT"
CODEX_CLI_MODEL = "CHATGPT_SESSION"
PROVIDER_CONNECTED_UNATTESTED = "PROVIDER_CONNECTED_UNATTESTED"
PROVIDER_NOT_CONNECTED = "NOT_CONNECTED"
PROVIDER_UNAVAILABLE = "UNAVAILABLE"
PROVIDER_ATTESTATION_SCOPE = "UNATTESTED"
OPENAI_RESPONSES_ENDPOINT = "https://api.openai.com/v1/responses"
DEFAULT_OPENAI_MODEL = "gpt-5.6-sol"
ALLOWED_OPENAI_MODELS = frozenset({"gpt-5.6-sol", "gpt-5.6-terra", "gpt-5.6-luna"})
PROVIDER_STATUS_DOMAIN = "AI-CONTROL-PLANE/AF06/PROVIDER_STATUS"
MAX_PROMPT_BYTES = 4096
MAX_RESPONSE_BYTES = 65536
MAX_EVIDENCE_BYTES = 65536
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
_SECRET_PATTERNS = (
    re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/-]{8,}"),
    re.compile(r"\bsk-[A-Za-z0-9_-]{8,}"),
    re.compile(r"(?i)\b(api[_-]?key|token|secret|password|authorization)\s*[:=]\s*\S+"),
)


class ProviderBackend(Protocol):
    """Provider-neutral bounded read-only backend contract."""

    provider_kind: str
    model: str

    def configured(self) -> bool: ...
    def probe(self) -> "ProviderCallResult": ...
    def execute(self, dispatch: DispatchEnvelope) -> "ProviderEvidence": ...


def _identifier(value: object, label: str) -> str:
    if not isinstance(value, str) or not _IDENTIFIER.fullmatch(value):
        raise BlockedError(f"invalid {label}")
    return value


def _finite_time(value: object) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise BlockedError("invalid provider timestamp")
    result = float(value)
    if not math.isfinite(result) or result < 0:
        raise BlockedError("invalid provider timestamp")
    return result


def _redact(text: str) -> str:
    value = clean(text)
    for pattern in _SECRET_PATTERNS:
        value = pattern.sub("[REDACTED]", value)
    return value[:16384]


def provider_signed_bytes(frame: dict[str, object]) -> bytes:
    body = {key: value for key, value in frame.items() if key != "signature"}
    return PROVIDER_STATUS_DOMAIN.encode("ascii") + b"\n" + canonical_json(body)


def deterministic_read_only_instruction(dispatch: DispatchEnvelope) -> str:
    if dispatch.protocol_version != AF05_PROTOCOL_VERSION:
        raise BlockedError("unsupported dispatch protocol")
    if dispatch.capability not in ALLOWED_CAPABILITIES:
        raise BlockedError("provider capability prohibited")
    target = _identifier(dispatch.target_project, "target_project")
    capability = _identifier(dispatch.capability, "capability")
    task = _identifier(dispatch.task_id, "task_id")
    instruction = (
        "You are executing a governed read-only control-plane task. "
        "Do not call tools, execute commands, mutate files, mutate Git, change credentials, "
        "control processes, place orders, or claim access you do not have. "
        f"Task={task}; target={target}; capability={capability}. "
        "Return a concise text result that describes only what can be concluded from these supplied metadata. "
        "Do not claim PASS, certification, provider attestation, or project mutation."
    )
    if len(instruction.encode("utf-8")) > MAX_PROMPT_BYTES:
        raise BlockedError("provider prompt too large")
    return instruction


@dataclass(frozen=True)
class ProviderCallResult:
    response_id: str
    reported_model: str
    output_text: str


@dataclass(frozen=True)
class ProviderEvidence:
    evidence_id: str
    sha256: str
    payload: bytes
    response_id: str
    requested_model: str
    reported_model: str
    connection_scope: str = PROVIDER_CONNECTED_UNATTESTED


class OpenAIResponsesClient:
    """Bounded text-only Responses API client; never stores API credentials."""

    def __init__(
        self,
        *,
        model: str = DEFAULT_OPENAI_MODEL,
        endpoint: str = OPENAI_RESPONSES_ENDPOINT,
        api_key_provider: Callable[[], str | None] | None = None,
        timeout_seconds: float = 30.0,
        max_response_bytes: int = MAX_RESPONSE_BYTES,
        transport: Callable[[urlrequest.Request, float, int], bytes] | None = None,
    ):
        if model not in ALLOWED_OPENAI_MODELS:
            raise BlockedError("unsupported OpenAI model")
        if endpoint != OPENAI_RESPONSES_ENDPOINT:
            raise BlockedError("provider endpoint not allowlisted")
        if isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, (int, float)) or not 1 <= float(timeout_seconds) <= 120:
            raise BlockedError("invalid provider timeout")
        if isinstance(max_response_bytes, bool) or not isinstance(max_response_bytes, int) or not 1024 <= max_response_bytes <= MAX_RESPONSE_BYTES:
            raise BlockedError("invalid provider response bound")
        self.provider_kind = PROVIDER_KIND
        self.model = model
        self.endpoint = endpoint
        self.timeout_seconds = float(timeout_seconds)
        self.max_response_bytes = max_response_bytes
        self._api_key_provider = api_key_provider or (lambda: os.environ.get("OPENAI_API_KEY"))
        self._transport = transport or self._urllib_transport

    def configured(self) -> bool:
        value = self._api_key_provider()
        return isinstance(value, str) and bool(value.strip())

    @staticmethod
    def _urllib_transport(req: urlrequest.Request, timeout: float, max_bytes: int) -> bytes:
        try:
            context = ssl.create_default_context()
            with urlrequest.urlopen(req, timeout=timeout, context=context) as response:
                status = int(getattr(response, "status", 0) or 0)
                if status != 200:
                    raise BlockedError("provider HTTP failure")
                data = response.read(max_bytes + 1)
        except BlockedError:
            raise
        except (urlerror.HTTPError, urlerror.URLError, TimeoutError, OSError) as exc:
            raise BlockedError("provider request unavailable") from exc
        if len(data) > max_bytes:
            raise BlockedError("provider response oversized")
        return data

    def _call(self, input_text: str, *, max_output_tokens: int) -> ProviderCallResult:
        if not isinstance(input_text, str) or not input_text.strip() or len(input_text.encode("utf-8")) > MAX_PROMPT_BYTES:
            raise BlockedError("invalid provider input")
        if isinstance(max_output_tokens, bool) or not isinstance(max_output_tokens, int) or not 1 <= max_output_tokens <= 4096:
            raise BlockedError("invalid provider output token bound")
        api_key = self._api_key_provider()
        if not isinstance(api_key, str) or not api_key.strip():
            raise BlockedError("provider credential unavailable")
        body = canonical_json({
            "model": self.model,
            "input": input_text,
            "store": False,
            "tools": [],
            "max_output_tokens": max_output_tokens,
            "reasoning": {"effort": "none"},
        })
        req = urlrequest.Request(
            self.endpoint,
            data=body,
            method="POST",
            headers={
                "Authorization": f"Bearer {api_key.strip()}",
                "Content-Type": "application/json",
                "User-Agent": "AI-CONTROL-PLANE-AF06/1",
            },
        )
        raw = self._transport(req, self.timeout_seconds, self.max_response_bytes)
        if not isinstance(raw, bytes):
            raise BlockedError("provider response must be bytes")
        if len(raw) > self.max_response_bytes:
            raise BlockedError("provider response oversized")
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise BlockedError("provider response malformed") from exc
        if not isinstance(payload, dict) or payload.get("object") != "response" or payload.get("status") != "completed":
            raise BlockedError("provider response incomplete")
        response_id = _identifier(payload.get("id"), "provider_response_id")
        reported_model = _identifier(payload.get("model"), "provider_model")
        if reported_model != self.model:
            raise BlockedError("provider model mismatch")
        chunks: list[str] = []
        output = payload.get("output")
        if not isinstance(output, list):
            raise BlockedError("provider response schema invalid")
        for item in output:
            if not isinstance(item, dict) or item.get("type") != "message":
                continue
            content = item.get("content")
            if not isinstance(content, list):
                continue
            for part in content:
                if isinstance(part, dict) and part.get("type") == "output_text" and isinstance(part.get("text"), str):
                    chunks.append(part["text"])
        text = _redact("\n".join(chunks).strip())
        if not text:
            raise BlockedError("provider returned no bounded text")
        if len(text.encode("utf-8")) > MAX_EVIDENCE_BYTES // 2:
            raise BlockedError("provider output oversized")
        return ProviderCallResult(response_id, reported_model, text)

    def probe(self) -> ProviderCallResult:
        return self._call(
            "Reply with the exact text READ_ONLY_PROVIDER_OK. Do not call tools or make external claims.",
            max_output_tokens=32,
        )

    def execute(self, dispatch: DispatchEnvelope) -> ProviderEvidence:
        instruction = deterministic_read_only_instruction(dispatch)
        result = self._call(instruction, max_output_tokens=1024)
        binding = {
            "af06_protocol_version": AF06_PROTOCOL_VERSION,
            "provider_kind": self.provider_kind,
            "connection_scope": PROVIDER_CONNECTED_UNATTESTED,
            "provider_attestation_scope": PROVIDER_ATTESTATION_SCOPE,
            "requested_model": self.model,
            "reported_model": result.reported_model,
            "provider_response_id": result.response_id,
            "dispatch": asdict(dispatch),
            "output_text": result.output_text,
        }
        payload = canonical_json(binding)
        if len(payload) > MAX_EVIDENCE_BYTES:
            raise BlockedError("provider evidence oversized")
        digest = hashlib.sha256(payload).hexdigest()
        evidence_id = "af06-" + hashlib.sha256(
            canonical_json({"dispatch_id": dispatch.dispatch_id, "response_id": result.response_id, "sha256": digest})
        ).hexdigest()[:48]
        return ProviderEvidence(evidence_id, digest, payload, result.response_id, self.model, result.reported_model)


class ProviderBoundGateway:
    """AF-05-compatible gateway that additionally requires fresh signed provider truth."""

    def __init__(self, base: AuthenticatedExternalGateway):
        self.base = base
        self.store = base.store
        self.registry = base.registry
        self.transport = base.transport
        self._init_schema()

    def _init_schema(self) -> None:
        self.store.db.executescript("""
CREATE TABLE IF NOT EXISTS af06_provider_status(
 worker_id TEXT PRIMARY KEY, session_id TEXT NOT NULL, key_id TEXT NOT NULL,
 provider_kind TEXT NOT NULL, model TEXT NOT NULL, connection_state TEXT NOT NULL,
 attestation_scope TEXT NOT NULL, sequence INTEGER NOT NULL, observed_at REAL NOT NULL,
 last_message_id TEXT NOT NULL, provider_response_id TEXT);
CREATE TABLE IF NOT EXISTS af06_provider_messages(
 message_id TEXT PRIMARY KEY, worker_id TEXT NOT NULL, session_id TEXT NOT NULL,
 sequence INTEGER NOT NULL, accepted_at REAL NOT NULL);
""")

    def accept_provider_status(self, frame: dict[str, object], *, now: float) -> None:
        expected = {
            "protocol_version", "worker_id", "key_id", "session_id", "message_id",
            "sequence", "observed_at", "provider_kind", "model", "connection_state",
            "attestation_scope", "provider_response_id", "signature",
        }
        if not isinstance(frame, dict) or set(frame) != expected:
            raise BlockedError("malformed provider status")
        n = self.store.now(now)
        worker = _identifier(frame.get("worker_id"), "worker_id")
        key_id = _identifier(frame.get("key_id"), "key_id")
        session_id = _identifier(frame.get("session_id"), "session_id")
        message_id = _identifier(frame.get("message_id"), "message_id")
        sequence = frame.get("sequence")
        observed_at = _finite_time(frame.get("observed_at"))
        if isinstance(sequence, bool) or not isinstance(sequence, int) or sequence <= 0:
            raise BlockedError("invalid provider sequence")
        if frame.get("protocol_version") != AF06_PROTOCOL_VERSION or frame.get("provider_kind") not in {PROVIDER_KIND, CODEX_CLI_PROVIDER_KIND}:
            raise BlockedError("unsupported provider protocol")
        model = frame.get("model")
        provider_kind = frame.get("provider_kind")
        allowed_models = ALLOWED_OPENAI_MODELS if provider_kind == PROVIDER_KIND else {CODEX_CLI_MODEL}
        if model not in allowed_models:
            raise BlockedError("unsupported provider model")
        connection_state = frame.get("connection_state")
        if connection_state not in {PROVIDER_CONNECTED_UNATTESTED, PROVIDER_NOT_CONNECTED, PROVIDER_UNAVAILABLE}:
            raise BlockedError("forged provider state")
        if frame.get("attestation_scope") != PROVIDER_ATTESTATION_SCOPE:
            raise BlockedError("provider attestation overclaim")
        response_id = frame.get("provider_response_id")
        if response_id is not None:
            response_id = _identifier(response_id, "provider_response_id")
        if connection_state == PROVIDER_CONNECTED_UNATTESTED and response_id is None:
            raise BlockedError("connected provider requires proof request id")
        profile = self.base._trusted(worker)
        if key_id != profile.profile.key_id:
            raise BlockedError("provider key binding mismatch")
        session = self.store.db.execute("SELECT * FROM af05_sessions WHERE worker_id=?", (worker,)).fetchone()
        if not session or session["state"] != "AUTHENTICATED" or session["session_id"] != session_id or session["key_id"] != key_id:
            raise BlockedError("provider session unavailable")
        if observed_at > n + 1 or n - observed_at > profile.profile.heartbeat_sla:
            raise BlockedError("stale provider status")
        signature = frame.get("signature")
        if not isinstance(signature, str):
            raise BlockedError("missing provider signature")
        try:
            profile.public_key.verify(base64.b64decode(signature, validate=True), provider_signed_bytes(frame))
        except (ValueError, InvalidSignature) as exc:
            raise BlockedError("invalid provider signature") from exc
        self.store.db.execute("BEGIN IMMEDIATE")
        try:
            previous = self.store.db.execute(
                "SELECT sequence,session_id FROM af06_provider_status WHERE worker_id=?",
                (worker,),
            ).fetchone()
            if previous and previous["session_id"] == session_id and sequence <= previous["sequence"]:
                raise BlockedError("provider status replay")
            if self.store.db.execute(
                "SELECT 1 FROM af06_provider_messages WHERE message_id=?", (message_id,)
            ).fetchone():
                raise BlockedError("provider status replay")
            self.store.db.execute(
                "INSERT INTO af06_provider_messages VALUES(?,?,?,?,?)",
                (message_id, worker, session_id, sequence, n),
            )
            self.store.db.execute(
                "INSERT INTO af06_provider_status VALUES(?,?,?,?,?,?,?,?,?,?,?) "
                "ON CONFLICT(worker_id) DO UPDATE SET session_id=excluded.session_id,key_id=excluded.key_id,provider_kind=excluded.provider_kind,model=excluded.model,connection_state=excluded.connection_state,attestation_scope=excluded.attestation_scope,sequence=excluded.sequence,observed_at=excluded.observed_at,last_message_id=excluded.last_message_id,provider_response_id=excluded.provider_response_id",
                (worker, session_id, key_id, frame["provider_kind"], model, connection_state, PROVIDER_ATTESTATION_SCOPE, sequence, observed_at, message_id, response_id),
            )
            self.store.db.execute("COMMIT")
        except (BlockedError, sqlite3.IntegrityError) as exc:
            if self.store.db.in_transaction:
                self.store.db.execute("ROLLBACK")
            if isinstance(exc, sqlite3.IntegrityError):
                raise BlockedError("provider status replay") from exc
            raise
        except Exception:
            if self.store.db.in_transaction:
                self.store.db.execute("ROLLBACK")
            raise

    def eligible_sessions(self, *, capability: str, target_project: str, now: float):
        n = self.store.now(now)
        eligible = []
        for worker_id, session_id in self.base.eligible_sessions(capability=capability, target_project=target_project, now=n):
            row = self.store.db.execute("SELECT * FROM af06_provider_status WHERE worker_id=?", (worker_id,)).fetchone()
            profile = self.base._trusted(worker_id)
            if not row or row["session_id"] != session_id or row["connection_state"] != PROVIDER_CONNECTED_UNATTESTED:
                continue
            if row["attestation_scope"] != PROVIDER_ATTESTATION_SCOPE or n - row["observed_at"] > profile.profile.heartbeat_sla or row["observed_at"] > n + 1:
                continue
            eligible.append((worker_id, session_id))
        return sorted(eligible)

    def session_projection(self, *, now: float):
        n = self.store.now(now)
        output = []
        for item in self.base.session_projection(now=n):
            row = self.store.db.execute("SELECT * FROM af06_provider_status WHERE worker_id=?", (item["worker_id"],)).fetchone()
            current = "UNKNOWN"
            last_known = None
            response_id = None
            model = None
            if row:
                last_known = row["connection_state"]
                response_id = row["provider_response_id"]
                model = row["model"]
                try:
                    profile = self.base._trusted(item["worker_id"])
                    if item.get("status") == "AVAILABLE" and row["session_id"] == item.get("session_status"):
                        fresh = row["observed_at"] <= n + 1 and n - row["observed_at"] <= profile.profile.heartbeat_sla
                        current = row["connection_state"] if fresh else "STALE"
                except BlockedError:
                    current = "UNKNOWN"
            # session_projection's session_status is a state, not id; use the durable row to bind current truth.
            session = self.store.db.execute("SELECT session_id,state FROM af05_sessions WHERE worker_id=?", (item["worker_id"],)).fetchone()
            if row and session and session["state"] == "AUTHENTICATED" and row["session_id"] == session["session_id"]:
                profile = self.base._trusted(item["worker_id"])
                fresh = row["observed_at"] <= n + 1 and n - row["observed_at"] <= profile.profile.heartbeat_sla
                current = row["connection_state"] if fresh else "STALE"
            elif row:
                current = "UNKNOWN"
            output.append({**item,
                "adapter_kind": item.get("provider_kind", "UNKNOWN"),
                "adapter_status": item.get("status", "UNKNOWN"),
                "provider_kind": row["provider_kind"] if row else "UNKNOWN",
                "provider_connection_status": current,
                "provider_last_known_status": last_known,
                "provider_attestation_scope": PROVIDER_ATTESTATION_SCOPE if row else "UNKNOWN",
                "provider_model": model,
                "last_provider_response_id": response_id,
                "provider_execution_eligible": bool(item.get("status") == "AVAILABLE" and current == PROVIDER_CONNECTED_UNATTESTED),
            })
        return output

    def dispatch_projection(self):
        return self.base.dispatch_projection()

    def issue_challenge(self, *args, **kwargs): return self.base.issue_challenge(*args, **kwargs)
    def authenticate_session(self, *args, **kwargs): return self.base.authenticate_session(*args, **kwargs)
    def heartbeat(self, *args, **kwargs): return self.base.heartbeat(*args, **kwargs)
    def dispatch(self, *args, **kwargs): return self.base.dispatch(*args, **kwargs)
    def acknowledge(self, *args, **kwargs): return self.base.acknowledge(*args, **kwargs)
    def result(self, *args, **kwargs): return self.base.result(*args, **kwargs)
    def revoke(self, *args, **kwargs): return self.base.revoke(*args, **kwargs)


class OpenAIReadOnlyWorker:
    """Worker-side AF-06 adapter. Private key is supplied by the host and never persisted."""

    def __init__(self, *, profile: TrustedWorkerProfile, private_key: Ed25519PrivateKey,
                 session_id: str, client: ProviderBackend):
        self.profile = profile
        self.private_key = private_key
        self.session_id = _identifier(session_id, "session_id")
        self.client = client
        self.provider_sequence = 0
        self.last_connection_state = PROVIDER_NOT_CONNECTED
        self.last_provider_response_id: str | None = None

    def _sign_af05(self, domain: str, frame: dict[str, object]) -> dict[str, object]:
        value = dict(frame)
        value["signature"] = base64.b64encode(self.private_key.sign(signed_bytes(DOMAINS[domain], value))).decode("ascii")
        return value

    def provider_status_frame(self, *, observed_at: float, probe: bool = False) -> dict[str, object]:
        self.provider_sequence += 1
        connection_state = PROVIDER_NOT_CONNECTED
        response_id = None
        if self.client.configured():
            if probe:
                try:
                    result = self.client.probe()
                    connection_state = PROVIDER_CONNECTED_UNATTESTED
                    response_id = result.response_id
                except BlockedError:
                    connection_state = PROVIDER_UNAVAILABLE
            else:
                connection_state = PROVIDER_UNAVAILABLE
        self.last_connection_state = connection_state
        self.last_provider_response_id = response_id
        frame = {
            "protocol_version": AF06_PROTOCOL_VERSION,
            "worker_id": self.profile.worker_id,
            "key_id": self.profile.key_id,
            "session_id": self.session_id,
            "message_id": f"af06-provider-{self.session_id[:24]}-{self.provider_sequence}",
            "sequence": self.provider_sequence,
            "observed_at": _finite_time(observed_at),
            "provider_kind": self.client.provider_kind,
            "model": self.client.model,
            "connection_state": connection_state,
            "attestation_scope": PROVIDER_ATTESTATION_SCOPE,
            "provider_response_id": response_id,
        }
        frame["signature"] = base64.b64encode(self.private_key.sign(provider_signed_bytes(frame))).decode("ascii")
        return frame

    def _validate_dispatch_authority(self, dispatch: DispatchEnvelope) -> None:
        if dispatch.protocol_version != AF05_PROTOCOL_VERSION:
            raise BlockedError("unsupported dispatch protocol")
        if dispatch.worker_id != self.profile.worker_id or dispatch.session_id != self.session_id:
            raise BlockedError("provider dispatch identity mismatch")
        if dispatch.capability not in self.profile.capabilities or dispatch.target_project not in self.profile.allowed_targets:
            raise BlockedError("provider dispatch capability or target mismatch")

    def ack_frame(self, dispatch: DispatchEnvelope, *, sequence: int, observed_at: float) -> dict[str, object]:
        self._validate_dispatch_authority(dispatch)
        return self._sign_af05("ACK", {
            "protocol_version": AF05_PROTOCOL_VERSION,
            "worker_id": self.profile.worker_id,
            "key_id": self.profile.key_id,
            "session_id": self.session_id,
            "message_id": f"af06-ack-{dispatch.dispatch_id[:24]}-{sequence}",
            "sequence": sequence,
            "observed_at": _finite_time(observed_at),
            "dispatch_id": dispatch.dispatch_id,
            "task_id": dispatch.task_id,
            "lease_id": dispatch.lease_id,
        })

    def execute_result_frame(self, dispatch: DispatchEnvelope, *, sequence: int, observed_at: float,
                             evidence_sink: Callable[[str, bytes], None]) -> dict[str, object]:
        self._validate_dispatch_authority(dispatch)
        if self.last_connection_state != PROVIDER_CONNECTED_UNATTESTED:
            raise BlockedError("provider not connected")
        evidence = self.client.execute(dispatch)
        evidence_sink(evidence.evidence_id, evidence.payload)
        return self._sign_af05("RESULT", {
            "protocol_version": AF05_PROTOCOL_VERSION,
            "worker_id": self.profile.worker_id,
            "key_id": self.profile.key_id,
            "session_id": self.session_id,
            "message_id": f"af06-result-{dispatch.dispatch_id[:20]}-{sequence}",
            "sequence": sequence,
            "observed_at": _finite_time(observed_at),
            "dispatch_id": dispatch.dispatch_id,
            "task_id": dispatch.task_id,
            "lease_id": dispatch.lease_id,
            "status": "SUCCEEDED",
            "evidence_id": evidence.evidence_id,
            "evidence_sha256": evidence.sha256,
        })


assert REAL_PROJECT_MUTATION_ENABLED is False
