"""Isolated entrypoint tests; never use the host credential or real network."""
import ast
import json
from pathlib import Path

import pytest

from src.autonomy import smoke
from src.autonomy.provider import OpenAIResponsesClient
from src.autonomy.transport import DurableLocalSpool


@pytest.fixture(autouse=True)
def isolated(monkeypatch, tmp_path):
    monkeypatch.setenv("OPENAI_API_KEY", "synthetic-smoke-credential")
    for name in ("REAL_PROJECT_MUTATION_ENABLED", "CONTROL_PLANE_EXECUTE_MUTATING_DIRECTIVES",
                 "ARBITRARY_PROVIDER_TOOLS_ENABLED"):
        monkeypatch.setenv(name, "false")
    monkeypatch.setattr(smoke.tempfile, "gettempdir", lambda: str(tmp_path))
    calls = []

    def transport(request, timeout, maximum):
        body = json.loads(request.data)
        assert body["tools"] == [] and body["store"] is False
        assert request.full_url == "https://api.openai.com/v1/responses"
        calls.append(body)
        return response()

    monkeypatch.setattr(OpenAIResponsesClient, "_urllib_transport", staticmethod(transport))
    return calls


def response(model="gpt-5.6-sol", text="Bounded metadata result"):
    return json.dumps(dict(id="resp_smoke", object="response", status="completed", model=model,
                          output=[dict(type="message", content=[dict(type="output_text", text=text)])])).encode()


def test_missing_credential_before_network(monkeypatch, isolated):
    monkeypatch.delenv("OPENAI_API_KEY")
    result = smoke.run_smoke()
    assert result["REAL_PROVIDER_SMOKE"] == "BLOCKED_CREDENTIAL"
    assert not isolated


@pytest.mark.parametrize("name", ["REAL_PROJECT_MUTATION_ENABLED", "CONTROL_PLANE_EXECUTE_MUTATING_DIRECTIVES",
                                 "ARBITRARY_PROVIDER_TOOLS_ENABLED"])
@pytest.mark.parametrize("source", ["environment", "constant"])
def test_flags_block(monkeypatch, isolated, name, source):
    if source == "environment":
        monkeypatch.setenv(name, "true")
    else:
        monkeypatch.setattr(smoke, name, True)
    assert smoke.run_smoke()["REAL_PROVIDER_SMOKE"] == "BLOCKED_FLAGS"
    assert not isolated


def test_network_failure_safe(monkeypatch):
    def fail(*args):
        raise OSError("synthetic-smoke-credential")
    monkeypatch.setattr(OpenAIResponsesClient, "_urllib_transport", staticmethod(fail))
    result = smoke.run_smoke()
    assert result["REAL_PROVIDER_SMOKE"].startswith("BLOCKED_")
    assert result["PROVIDER_REQUESTS_PERFORMED"] == 1
    assert result["REVIEW_PENDING_REACHED"] is False
    assert "synthetic-smoke-credential" not in str(result)


def test_wrong_model(monkeypatch):
    monkeypatch.setattr(OpenAIResponsesClient, "_urllib_transport", staticmethod(lambda *args: response(model="wrong")))
    assert smoke.run_smoke()["REAL_PROVIDER_SMOKE"] == "BLOCKED_PROBE"


@pytest.mark.parametrize("kind", ["missing", "bad"])
def test_independent_evidence_blocks(monkeypatch, kind):
    def resolve(self, identity):
        if kind == "missing":
            raise smoke.BlockedError("missing")
        return b"tampered"
    monkeypatch.setattr(DurableLocalSpool, "resolve_evidence", resolve)
    result = smoke.run_smoke()
    assert result["REAL_PROVIDER_SMOKE"] == "BLOCKED_RESULT"
    assert result["TASK_FINAL_STATE"] == "RUNNING"
    assert not result["REVIEW_PENDING_REACHED"]


def test_success_review_only(isolated, tmp_path, monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("automatic review completion")
    monkeypatch.setattr(smoke.AutonomyStore, "complete_after_review", forbidden)
    result = smoke.run_smoke()
    assert result["REAL_PROVIDER_SMOKE"] == "PASS"
    assert result["TASK_FINAL_STATE"] == "REVIEW_PENDING"
    assert result["REVIEW_PENDING_REACHED"] is True
    assert result["PROVIDER_TRUST_SCOPE"] == "PROVIDER_CONNECTED_UNATTESTED"
    assert result["PROVIDER_REQUESTS_PERFORMED"] == len(isolated) == 2
    assert not list(tmp_path.iterdir())


def test_credential_echo_never_persisted(monkeypatch, capsys, tmp_path):
    monkeypatch.setattr(OpenAIResponsesClient, "_urllib_transport", staticmethod(
        lambda *args: response(text="synthetic-smoke-credential")))
    assert smoke.main() == 1
    output = capsys.readouterr()
    assert "synthetic-smoke-credential" not in output.out + output.err
    assert not list(tmp_path.iterdir())


def test_no_mutation_surface():
    tree = ast.parse(Path(smoke.__file__).read_text())
    imports = {node.module for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)}
    imports.update(alias.name for node in ast.walk(tree) if isinstance(node, ast.Import) for alias in node.names)
    assert not imports.intersection({"subprocess", "shutil", "signal", "ctypes"})
    calls = {node.func.attr for node in ast.walk(tree) if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)}
    assert not calls.intersection({"system", "popen", "kill", "terminate", "complete_after_review", "run", "Popen"})


@pytest.mark.parametrize("fault", ["auth", "future", "stale", "binding", "expiry", "oversize"])
def test_protocol_faults_never_pass(monkeypatch, fault):
    if fault == "auth":
        def reject(*args, **kwargs):
            raise smoke.BlockedError("authentication")
        monkeypatch.setattr(smoke.ProviderBoundGateway, "authenticate_session", reject)
    elif fault in {"future", "stale"}:
        original = smoke.OpenAIReadOnlyWorker.provider_status_frame
        def status(self, *, observed_at, probe):
            return original(self, observed_at=observed_at + (300 if fault == "future" else -300), probe=probe)
        monkeypatch.setattr(smoke.OpenAIReadOnlyWorker, "provider_status_frame", status)
    elif fault == "binding":
        original = smoke.OpenAIReadOnlyWorker.ack_frame
        def ack(self, *args, **kwargs):
            frame = original(self, *args, **kwargs)
            frame["lease_id"] = "wrong"
            return frame
        monkeypatch.setattr(smoke.OpenAIReadOnlyWorker, "ack_frame", ack)
    elif fault == "expiry":
        original = smoke.ProviderBoundGateway.result
        def late(self, frame, *, now):
            return original(self, frame, now=now + 300)
        monkeypatch.setattr(smoke.ProviderBoundGateway, "result", late)
    else:
        monkeypatch.setattr(OpenAIResponsesClient, "_urllib_transport", staticmethod(lambda *args: b"x" * 65537))
    result = smoke.run_smoke()
    assert result["REAL_PROVIDER_SMOKE"].startswith("BLOCKED_")
    assert result["REVIEW_PENDING_REACHED"] is False
    assert result["TASK_FINAL_STATE"] != "REVIEW_PENDING"
