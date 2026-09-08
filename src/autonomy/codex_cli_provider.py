"""AF-06 bounded Codex CLI backend authenticated through the existing ChatGPT session."""
from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import tempfile
from dataclasses import asdict
from pathlib import Path

from .protocol import DispatchEnvelope
from .provider import (
    AF06_PROTOCOL_VERSION,
    CODEX_CLI_MODEL,
    CODEX_CLI_PROVIDER_KIND,
    MAX_EVIDENCE_BYTES,
    MAX_PROMPT_BYTES,
    MAX_RESPONSE_BYTES,
    PROVIDER_ATTESTATION_SCOPE,
    PROVIDER_CONNECTED_UNATTESTED,
    ProviderCallResult,
    ProviderEvidence,
    _identifier,
    _redact,
    deterministic_read_only_instruction,
)
from .store import BlockedError
from .trust import canonical_json


class CodexCliChatGPTClient:
    """Single-purpose Codex CLI backend with a fixed read-only argv boundary."""

    provider_kind = CODEX_CLI_PROVIDER_KIND
    model = CODEX_CLI_MODEL

    def __init__(
        self,
        *,
        executable: Path | str,
        expected_executable_sha256: str,
        expected_version: str,
        working_directory: Path | str,
        timeout_seconds: float = 120.0,
        max_stdout_bytes: int = MAX_RESPONSE_BYTES,
        max_stderr_bytes: int = 16384,
    ):
        candidate = Path(executable)
        try:
            resolved = candidate.resolve(strict=True)
            workdir = Path(working_directory).resolve(strict=True)
        except OSError as exc:
            raise BlockedError("Codex executable or working directory unavailable") from exc
        if not resolved.is_file() or resolved.suffix.lower() != ".exe" or candidate.absolute() != resolved:
            raise BlockedError("Codex executable identity invalid")
        if not workdir.is_dir():
            raise BlockedError("Codex working directory invalid")
        if not re.fullmatch(r"[0-9a-f]{64}", expected_executable_sha256):
            raise BlockedError("Codex executable digest invalid")
        actual_digest = hashlib.sha256(resolved.read_bytes()).hexdigest()
        if actual_digest != expected_executable_sha256:
            raise BlockedError("Codex executable digest mismatch")
        if not isinstance(expected_version, str) or not expected_version.startswith("codex-cli "):
            raise BlockedError("Codex version expectation invalid")
        if isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, (int, float)) or not 5 <= float(timeout_seconds) <= 300:
            raise BlockedError("invalid Codex timeout")
        if isinstance(max_stdout_bytes, bool) or not isinstance(max_stdout_bytes, int) or not 1024 <= max_stdout_bytes <= MAX_RESPONSE_BYTES:
            raise BlockedError("invalid Codex stdout bound")
        if isinstance(max_stderr_bytes, bool) or not isinstance(max_stderr_bytes, int) or not 1024 <= max_stderr_bytes <= MAX_RESPONSE_BYTES:
            raise BlockedError("invalid Codex stderr bound")
        self.executable = resolved
        self.executable_sha256 = actual_digest
        self.expected_version = expected_version
        self.working_directory = workdir
        self.timeout_seconds = float(timeout_seconds)
        self.max_stdout_bytes = max_stdout_bytes
        self.max_stderr_bytes = max_stderr_bytes
        version = self._invoke(("--version",), timeout_seconds=10.0, output_file=None)
        if version.output_text.strip() != expected_version:
            raise BlockedError("Codex executable version mismatch")

    @staticmethod
    def _bounded_environment() -> dict[str, str]:
        allowed = {
            "APPDATA", "LOCALAPPDATA", "PROGRAMDATA", "SYSTEMDRIVE", "SYSTEMROOT",
            "TEMP", "TMP", "USERPROFILE", "WINDIR", "PATH", "CODEX_HOME",
        }
        return {name: value for name, value in os.environ.items() if name.upper() in allowed}

    def configured(self) -> bool:
        return True

    def _invoke(
        self,
        argv: tuple[str, ...],
        *,
        timeout_seconds: float,
        output_file: Path | None,
    ) -> ProviderCallResult:
        if not argv or any(not isinstance(value, str) or not value for value in argv):
            raise BlockedError("invalid Codex argv")
        with tempfile.TemporaryFile() as stdout_file, tempfile.TemporaryFile() as stderr_file:
            try:
                process = subprocess.Popen(
                    (str(self.executable), *argv),
                    cwd=self.working_directory,
                    env=self._bounded_environment(),
                    stdin=subprocess.DEVNULL,
                    stdout=stdout_file,
                    stderr=stderr_file,
                    shell=False,
                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                )
                try:
                    return_code = process.wait(timeout=timeout_seconds)
                except subprocess.TimeoutExpired as exc:
                    process.kill()
                    process.wait(timeout=5)
                    raise BlockedError("Codex invocation timeout") from exc
            except BlockedError:
                raise
            except OSError as exc:
                raise BlockedError("Codex invocation unavailable") from exc
            stdout_size = stdout_file.tell()
            stderr_size = stderr_file.tell()
            if stdout_size > self.max_stdout_bytes:
                raise BlockedError("Codex stdout oversized")
            if stderr_size > self.max_stderr_bytes:
                raise BlockedError("Codex stderr oversized")
            stdout_file.seek(0)
            stderr_file.seek(0)
            stdout = stdout_file.read()
            stderr_file.read()
        if return_code != 0:
            raise BlockedError("Codex invocation failed")
        if output_file is None:
            try:
                text = stdout.decode("utf-8").strip()
            except UnicodeDecodeError as exc:
                raise BlockedError("Codex output malformed") from exc
            return ProviderCallResult("codex-version", self.model, _redact(text))
        try:
            if not output_file.is_file() or output_file.stat().st_size > MAX_EVIDENCE_BYTES // 2:
                raise BlockedError("Codex final output unavailable or oversized")
            final_text = _redact(output_file.read_bytes().decode("utf-8").strip())
            events = [json.loads(line) for line in stdout.decode("utf-8").splitlines() if line.strip()]
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise BlockedError("Codex output malformed") from exc
        if not final_text:
            raise BlockedError("Codex returned no bounded text")
        thread_ids = []
        for event in events:
            if not isinstance(event, dict):
                raise BlockedError("Codex event schema invalid")
            if event.get("type") == "thread.started":
                thread_ids.append(_identifier(event.get("thread_id"), "Codex invocation id"))
            item = event.get("item")
            if isinstance(item, dict) and item.get("type") not in {"agent_message", "reasoning"}:
                raise BlockedError("Codex tool execution prohibited")
        invocation_id = thread_ids[-1] if thread_ids else "codex-" + hashlib.sha256(stdout).hexdigest()[:32]
        return ProviderCallResult(invocation_id, self.model, final_text)

    def _execute_prompt(self, prompt: str, *, max_output_tokens: int) -> ProviderCallResult:
        if max_output_tokens < 1 or max_output_tokens > 4096:
            raise BlockedError("invalid Codex output token bound")
        if not isinstance(prompt, str) or not prompt or len(prompt.encode("utf-8")) > MAX_PROMPT_BYTES:
            raise BlockedError("invalid Codex prompt")
        with tempfile.TemporaryDirectory(prefix="af06-codex-") as temporary:
            output_file = Path(temporary) / "final.txt"
            argv = (
                "--ask-for-approval", "never", "exec",
                "--sandbox", "read-only", "--ephemeral", "--ignore-user-config",
                "--skip-git-repo-check", "--json", "-C", str(self.working_directory),
                "--output-last-message", str(output_file), prompt,
            )
            return self._invoke(argv, timeout_seconds=self.timeout_seconds, output_file=output_file)

    def probe(self) -> ProviderCallResult:
        result = self._execute_prompt(
            "Reply with exactly READ_ONLY_PROVIDER_OK. Do not call tools or make external claims.",
            max_output_tokens=32,
        )
        if result.output_text != "READ_ONLY_PROVIDER_OK":
            raise BlockedError("Codex connectivity probe mismatch")
        return result

    def execute(self, dispatch: DispatchEnvelope) -> ProviderEvidence:
        result = self._execute_prompt(deterministic_read_only_instruction(dispatch), max_output_tokens=1024)
        binding = {
            "af06_protocol_version": AF06_PROTOCOL_VERSION,
            "provider_kind": self.provider_kind,
            "connection_scope": PROVIDER_CONNECTED_UNATTESTED,
            "provider_attestation_scope": PROVIDER_ATTESTATION_SCOPE,
            "codex_executable_sha256": self.executable_sha256,
            "codex_version": self.expected_version,
            "provider_invocation_id": result.response_id,
            "dispatch": asdict(dispatch),
            "output_text": result.output_text,
        }
        payload = canonical_json(binding)
        if len(payload) > MAX_EVIDENCE_BYTES:
            raise BlockedError("Codex evidence oversized")
        digest = hashlib.sha256(payload).hexdigest()
        evidence_id = "af06-codex-" + hashlib.sha256(
            canonical_json({"dispatch_id": dispatch.dispatch_id, "invocation_id": result.response_id, "sha256": digest})
        ).hexdigest()[:48]
        return ProviderEvidence(evidence_id, digest, payload, result.response_id, self.model, self.model)
