"""AF-06 bounded CODEX_CLI_CHATGPT backend tests."""
import hashlib
import json
import subprocess
from pathlib import Path

import pytest

from src.autonomy import (
    AF05_PROTOCOL_VERSION,
    BlockedError,
    CODEX_CLI_PROVIDER_KIND,
    CodexCliChatGPTClient,
    DispatchEnvelope,
    OpenAIReadOnlyWorker,
)


VERSION = "codex-cli 0.151.0-alpha.7.2"


class FakeCodexProcess:
    mode = "ok"
    calls = []

    def __init__(self, argv, **kwargs):
        self.argv = tuple(argv)
        self.return_code = 0
        type(self).calls.append(self.argv)
        stdout = kwargs["stdout"]
        stderr = kwargs["stderr"]
        if self.argv[-1] == "--version":
            stdout.write((VERSION + "\n").encode())
            return
        if self.mode == "nonzero":
            self.return_code = 7
            stderr.write(b"authorization=do-not-leak")
            return
        if self.mode == "oversized_stdout":
            stdout.write(b"x" * 70000)
            return
        if self.mode == "oversized_stderr":
            stderr.write(b"x" * 20000)
            return
        if self.mode == "malformed":
            stdout.write(b"not-json\n")
        else:
            item_type = "command_execution" if self.mode == "tool" else "agent_message"
            stdout.write(json.dumps({"type": "thread.started", "thread_id": "thread-1"}).encode() + b"\n")
            stdout.write(json.dumps({"type": "item.completed", "item": {"type": item_type}}).encode() + b"\n")
        output = Path(self.argv[self.argv.index("--output-last-message") + 1])
        text = "Bearer secret-token-123456" if self.mode == "secret" else "READ_ONLY_PROVIDER_OK"
        output.write_text(text, encoding="utf-8")

    def wait(self, timeout):
        if self.mode == "timeout" and self.argv[-1] != "--version":
            raise subprocess.TimeoutExpired(self.argv, timeout)
        return self.return_code

    def kill(self):
        self.return_code = -9
        self.mode = "killed"


@pytest.fixture
def codex_client(tmp_path, monkeypatch):
    executable = tmp_path / "codex.exe"
    executable.write_bytes(b"bounded-codex-test-executable")
    workdir = tmp_path / "workspace"
    workdir.mkdir()
    FakeCodexProcess.mode = "ok"
    FakeCodexProcess.calls = []
    monkeypatch.setattr(subprocess, "Popen", FakeCodexProcess)
    client = CodexCliChatGPTClient(
        executable=executable,
        expected_executable_sha256=hashlib.sha256(executable.read_bytes()).hexdigest(),
        expected_version=VERSION,
        working_directory=workdir,
        timeout_seconds=5,
    )
    return client


def envelope(**changes):
    values = dict(
        dispatch_id="dispatch-1", task_id="task-1", worker_id="worker-1",
        session_id="session-1", lease_id="lease-1", lease_expires_at=200,
        capability="OBSERVE_STATUS", target_project="PROJECT",
        protocol_version=AF05_PROTOCOL_VERSION,
    )
    values.update(changes)
    return DispatchEnvelope(**values)


def test_codex_executable_missing_is_blocked(tmp_path):
    with pytest.raises(BlockedError):
        CodexCliChatGPTClient(
            executable=tmp_path / "missing.exe", expected_executable_sha256="0" * 64,
            expected_version=VERSION, working_directory=tmp_path,
        )


def test_codex_executable_digest_contradiction_is_blocked(tmp_path):
    executable = tmp_path / "codex.exe"
    executable.write_bytes(b"binary")
    with pytest.raises(BlockedError, match="digest mismatch"):
        CodexCliChatGPTClient(
            executable=executable, expected_executable_sha256="0" * 64,
            expected_version=VERSION, working_directory=tmp_path,
        )


def test_codex_argv_is_direct_bounded_read_only_and_ephemeral(codex_client):
    assert codex_client.probe().output_text == "READ_ONLY_PROVIDER_OK"
    argv = FakeCodexProcess.calls[-1]
    assert argv[0] == str(codex_client.executable)
    assert argv[1:4] == ("--ask-for-approval", "never", "exec")
    assert ("--sandbox", "read-only") == argv[4:6]
    assert "--ephemeral" in argv and "--ignore-user-config" in argv and "--json" in argv
    assert "--output-last-message" in argv and str(codex_client.working_directory) in argv
    assert not any(value.lower().endswith(("cmd.exe", "powershell.exe", "pwsh.exe", "bash", "sh")) for value in argv)


@pytest.mark.parametrize("mode", ["tool"])
def test_codex_write_git_shell_or_process_tool_event_is_blocked(codex_client, mode):
    FakeCodexProcess.mode = mode
    with pytest.raises(BlockedError, match="tool execution prohibited"):
        codex_client.probe()


def test_codex_timeout_is_blocked(codex_client):
    FakeCodexProcess.mode = "timeout"
    with pytest.raises(BlockedError, match="timeout"):
        codex_client.probe()


def test_codex_nonzero_exit_is_not_success_and_stderr_is_not_leaked(codex_client):
    FakeCodexProcess.mode = "nonzero"
    with pytest.raises(BlockedError, match="invocation failed") as caught:
        codex_client.probe()
    assert "do-not-leak" not in str(caught.value)


@pytest.mark.parametrize(
    "mode, message",
    [("malformed", "output malformed"), ("oversized_stdout", "stdout oversized"),
     ("oversized_stderr", "stderr oversized")],
)
def test_codex_malformed_or_oversized_output_is_blocked(codex_client, mode, message):
    FakeCodexProcess.mode = mode
    with pytest.raises(BlockedError, match=message):
        codex_client.probe()


def test_codex_secret_shaped_output_is_redacted(codex_client):
    FakeCodexProcess.mode = "secret"
    result = codex_client._execute_prompt("bounded", max_output_tokens=8)
    assert "secret-token" not in result.output_text
    assert "REDACTED" in result.output_text


def test_codex_mutating_capability_is_blocked_before_invocation(codex_client):
    calls = len(FakeCodexProcess.calls)
    with pytest.raises(BlockedError):
        codex_client.execute(envelope(capability="WRITE_FILE"))
    assert len(FakeCodexProcess.calls) == calls


def test_codex_evidence_binds_complete_dispatch_and_executable(codex_client):
    evidence = codex_client.execute(envelope())
    body = json.loads(evidence.payload)
    assert evidence.sha256 == hashlib.sha256(evidence.payload).hexdigest()
    assert body["provider_kind"] == CODEX_CLI_PROVIDER_KIND
    assert body["codex_executable_sha256"] == codex_client.executable_sha256
    assert body["codex_version"] == VERSION
    assert body["dispatch"]["task_id"] == "task-1"
    assert body["dispatch"]["session_id"] == "session-1"
    assert body["dispatch"]["lease_id"] == "lease-1"
    assert body["dispatch"]["dispatch_id"] == "dispatch-1"


def test_codex_evidence_changes_for_lease_substitution(codex_client):
    first = codex_client.execute(envelope(lease_id="lease-1"))
    second = codex_client.execute(envelope(lease_id="lease-2"))
    assert first.sha256 != second.sha256
    assert first.evidence_id != second.evidence_id


def test_codex_signed_provider_status_is_accepted_and_projected(codex_client, tmp_path):
    from tests.test_autonomy_foundation_06 import environment

    _, gateway, private, profile, _, _ = environment(tmp_path)
    worker = OpenAIReadOnlyWorker(
        profile=profile, private_key=private, session_id="provider-session", client=codex_client
    )
    gateway.accept_provider_status(worker.provider_status_frame(observed_at=101, probe=True), now=101)
    projection = gateway.session_projection(now=101)[0]
    assert projection["provider_kind"] == CODEX_CLI_PROVIDER_KIND
    assert projection["provider_connection_status"] == "PROVIDER_CONNECTED_UNATTESTED"
    assert projection["provider_execution_eligible"] is True
