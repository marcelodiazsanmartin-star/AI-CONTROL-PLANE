"""Bounded durable local spool transport under a disposable AF-04 runtime root."""
from __future__ import annotations

import json
import os
from pathlib import Path

from .store import BlockedError
from .trust import canonical_json, identifier

MAX_FRAME_BYTES = 131_072
MAX_EVIDENCE_BYTES = 2_097_152
FILE_ATTRIBUTE_REPARSE_POINT = 0x400


class DurableLocalSpool:
    def __init__(self, runtime_root: Path | str):
        root = Path(runtime_root).resolve(strict=True)
        self.root = root / "external_workers"
        self.outbound = self.root / "outbound"
        self.inbound = self.root / "inbound"
        self.evidence = self.root / "evidence"
        self.processed = self.root / "processed"
        for path in (self.root, self.outbound, self.inbound, self.evidence, self.processed):
            path.mkdir(parents=True, exist_ok=True)
            self._safe_directory(path)

    def _safe_directory(self, path: Path) -> None:
        if path.is_symlink() or path.resolve(strict=True) != path.absolute():
            raise BlockedError("spool symlink traversal")
        if int(getattr(path.stat(follow_symlinks=False), "st_file_attributes", 0)) & FILE_ATTRIBUTE_REPARSE_POINT:
            raise BlockedError("spool reparse traversal")

    def _direct(self, directory: Path, identity: str, suffix: str) -> Path:
        name = identifier(identity, "spool identity") + suffix
        self._safe_directory(directory)
        path = directory / name
        if path.parent != directory or path.is_absolute() and path.parent != directory:
            raise BlockedError("invalid spool path")
        return path

    def write_outbound(self, message_id: str, body: dict[str, object]) -> Path:
        payload = canonical_json(body)
        if len(payload) > MAX_FRAME_BYTES: raise BlockedError("oversized transport frame")
        destination = self._direct(self.outbound, message_id, ".json")
        temporary = self._direct(self.outbound, message_id, ".tmp")
        if destination.exists() or temporary.exists(): raise BlockedError("duplicate transport frame")
        with open(temporary, "xb") as stream:
            stream.write(payload); stream.flush(); os.fsync(stream.fileno())
        os.replace(temporary, destination)
        return destination

    def read_frame(self, message_id: str) -> dict[str, object]:
        path = self._direct(self.inbound, message_id, ".json")
        if not path.exists() or not path.is_file() or path.is_symlink():
            raise BlockedError("inbound frame unavailable")
        raw = path.read_bytes()
        if len(raw) > MAX_FRAME_BYTES: raise BlockedError("oversized transport frame")
        try: value = json.loads(raw.decode("utf-8"))
        except Exception as exc: raise BlockedError("malformed transport frame") from exc
        if not isinstance(value, dict): raise BlockedError("invalid transport frame")
        return value

    def evidence_path(self, evidence_id: str) -> Path:
        return self._direct(self.evidence, evidence_id, ".bin")

    def resolve_evidence(self, evidence_id: str) -> bytes:
        path = self.evidence_path(evidence_id)
        if not path.exists() or not path.is_file() or path.is_symlink():
            raise BlockedError("evidence unavailable")
        if path.resolve(strict=True).parent != self.evidence.resolve(strict=True):
            raise BlockedError("evidence escaped ingress")
        size = path.stat(follow_symlinks=False).st_size
        if size < 0 or size > MAX_EVIDENCE_BYTES: raise BlockedError("oversized evidence")
        return path.read_bytes()
