"""Explicit one-shot AF-06 smoke; disposable state, no project execution."""
from __future__ import annotations

import base64
import json
import os
from pathlib import Path
import tempfile
import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from config import settings
from . import execution, protocol, runtime
from .external_gateway import AF05_PROTOCOL_VERSION, DOMAINS, AuthenticatedExternalGateway
from .provider import OpenAIReadOnlyWorker, OpenAIResponsesClient, ProviderBoundGateway
from .router import AgentRouter
from .runtime import RuntimeRootPolicy
from .store import AutonomyStore, BlockedError
from .trust import TrustedWorkerProfile, signed_bytes

REAL_PROJECT_MUTATION_ENABLED = False
CONTROL_PLANE_EXECUTE_MUTATING_DIRECTIVES = False
ARBITRARY_PROVIDER_TOOLS_ENABLED = False


def _check_flags() -> None:
    flags = [REAL_PROJECT_MUTATION_ENABLED, CONTROL_PLANE_EXECUTE_MUTATING_DIRECTIVES,
             ARBITRARY_PROVIDER_TOOLS_ENABLED, protocol.REAL_PROJECT_MUTATION_ENABLED,
             execution.REAL_PROJECT_MUTATION_ENABLED,
             runtime.CONTROL_PLANE_EXECUTE_MUTATING_DIRECTIVES]
    flags.extend(getattr(settings, name) for name in (
        "CONTROL_PLANE_EXECUTE_MUTATING_DIRECTIVES", "CONTROL_PLANE_WRITE_PROJECTS",
        "CONTROL_PLANE_RESTART_PROJECTS", "CONTROL_PLANE_CHANGE_STRATEGY",
        "CONTROL_PLANE_ENABLE_REAL_MONEY", "CONTROL_PLANE_EXECUTE_PROJECT_CODE"))
    if any(value is not False for value in flags):
        raise BlockedError("flags")
    for name in ("REAL_PROJECT_MUTATION_ENABLED", "CONTROL_PLANE_EXECUTE_MUTATING_DIRECTIVES",
                 "ARBITRARY_PROVIDER_TOOLS_ENABLED"):
        if os.environ.get(name, "false").lower() != "false":
            raise BlockedError("flags")


def run_smoke() -> dict[str, object]:
    """Run once using only process credentials and the production AF-06 transport.

    Request count records transport attempts, including failed requests. No exception
    text crosses this boundary. Temporary artifacts are removed before returning.
    """
    summary = dict(OPENAI_API_KEY_PROCESS_PRESENT=False, REAL_PROVIDER_SMOKE="BLOCKED_SETUP",
                   REAL_PROVIDER_CONNECTED=False, PROVIDER_TRUST_SCOPE="NOT_CONNECTED",
                   PROVIDER_REQUESTS_PERFORMED=0, PROVIDER_RESPONSE_ID="UNKNOWN",
                   TASK_FINAL_STATE="NOT_CREATED", REVIEW_PENDING_REACHED=False)
    stage = "FLAGS"
    store = None
    try:
        _check_flags()
        stage = "CREDENTIAL"
        summary["OPENAI_API_KEY_PROCESS_PRESENT"] = bool(os.environ.get("OPENAI_API_KEY", "").strip())
        if not summary["OPENAI_API_KEY_PROCESS_PRESENT"]:
            raise BlockedError("credential")
        stage = "SETUP"
        repository = Path(__file__).resolve().parents[2]
        parent = RuntimeRootPolicy((repository,)).validate(Path(tempfile.gettempdir()))

        def transport(request, timeout, maximum):
            _check_flags()
            summary["PROVIDER_REQUESTS_PERFORMED"] += 1
            raw = OpenAIResponsesClient._urllib_transport(request, timeout, maximum)
            if not isinstance(raw, bytes) or len(raw) > maximum:
                raise BlockedError("response bound")
            # Reject credential echoes before the adapter can produce evidence.
            credential = os.environ.get("OPENAI_API_KEY", "").strip()
            decoded = json.loads(raw)

            def contains_credential(value):
                if isinstance(value, str):
                    return credential in value
                if isinstance(value, dict):
                    return any(contains_credential(k) or contains_credential(v) for k, v in value.items())
                if isinstance(value, list):
                    return any(contains_credential(v) for v in value)
                return False

            if not credential or credential.encode() in raw or contains_credential(decoded):
                raise BlockedError("unsafe response")
            return raw

        with tempfile.TemporaryDirectory(prefix="af06-smoke-", dir=parent) as directory:
            root = RuntimeRootPolicy((repository,)).validate(Path(directory))
            store = AutonomyStore(root / "autonomy.sqlite")
            try:
                private = Ed25519PrivateKey.generate()
                public = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
                profile = TrustedWorkerProfile(
                    worker_id="af06-smoke", worker_kind="openai-adapter", key_id="ephemeral",
                    public_key_base64=base64.b64encode(public).decode("ascii"),
                    capabilities=("OBSERVE_STATUS",), allowed_targets=("AF06_SMOKE",),
                    max_capacity=1, heartbeat_sla=120.0)
                gateway = ProviderBoundGateway(AuthenticatedExternalGateway(
                    store, root, (profile,), repository_roots=(repository,)))
                worker = OpenAIReadOnlyWorker(profile=profile, private_key=private,
                                             session_id="smoke-session",
                                             client=OpenAIResponsesClient(transport=transport))

                def sign(domain, frame):
                    frame["signature"] = base64.b64encode(private.sign(signed_bytes(DOMAINS[domain], frame))).decode("ascii")
                    return frame

                stage = "AUTHENTICATION"
                challenge = gateway.issue_challenge(profile.worker_id, profile.key_id, now=time.time())
                gateway.authenticate_session(sign("SESSION", challenge.transcript(worker.session_id, 1)), now=time.time())
                stage = "PROBE"
                status = worker.provider_status_frame(observed_at=time.time(), probe=True)
                accepted_at = time.time()
                if status["observed_at"] > accepted_at:
                    raise BlockedError("future status")
                gateway.accept_provider_status(status, now=accepted_at)
                if status["connection_state"] != "PROVIDER_CONNECTED_UNATTESTED":
                    raise BlockedError("probe")
                summary["REAL_PROVIDER_CONNECTED"] = True
                summary["PROVIDER_TRUST_SCOPE"] = "PROVIDER_CONNECTED_UNATTESTED"
                # Response identifiers are untrusted provider data; do not expose them.
                stage = "ROUTING"
                now = time.time()
                gateway.heartbeat(sign("HEARTBEAT", dict(
                    protocol_version=AF05_PROTOCOL_VERSION, worker_id=profile.worker_id,
                    key_id=profile.key_id, session_id=worker.session_id, message_id="heartbeat-1",
                    sequence=1, observed_at=now, capacity=1)), now=time.time())
                store.create_task(task_id="smoke-task", directive_id="smoke-directive",
                                  target_project="AF06_SMOKE", capability="OBSERVE_STATUS",
                                  governance_allowed=True, retry_budget=0, now=time.time())
                envelopes = AgentRouter(store, gateway, batch_size=1, lease_seconds=120).route_once(now=time.time())
                if len(envelopes) != 1:
                    raise BlockedError("routing")
                dispatch = envelopes[0]
                stage = "ACK"
                gateway.acknowledge(worker.ack_frame(dispatch, sequence=2, observed_at=time.time()), now=time.time())
                if store.task("smoke-task")["state"] != "RUNNING":
                    raise BlockedError("ack")

                def evidence_sink(identity, payload):
                    with gateway.transport.evidence_path(identity).open("xb") as stream:
                        stream.write(payload)

                stage = "EXECUTION"
                result = worker.execute_result_frame(dispatch, sequence=3, observed_at=time.time(), evidence_sink=evidence_sink)
                stage = "RESULT"
                _check_flags()
                gateway.result(result, now=time.time())
                if store.task("smoke-task")["state"] != "REVIEW_PENDING":
                    raise BlockedError("review state")
            finally:
                try:
                    row = store.db.execute("SELECT state FROM tasks WHERE task_id=?", ("smoke-task",)).fetchone()
                    if row:
                        summary["TASK_FINAL_STATE"] = row["state"]
                finally:
                    store.close()
        summary["REVIEW_PENDING_REACHED"] = True
        summary["REAL_PROVIDER_SMOKE"] = "PASS"
    except Exception:
        summary["REAL_PROVIDER_SMOKE"] = "BLOCKED_" + stage
    return summary


def main() -> int:
    """Emit only a fixed safe summary, and return a nonzero exit code if blocked."""
    summary = run_smoke()
    for name, value in summary.items():
        print(f"{name}={str(value).lower() if isinstance(value, bool) else value}")
    return 0 if summary["REAL_PROVIDER_SMOKE"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
