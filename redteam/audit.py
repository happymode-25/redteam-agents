"""Append-only, hash-linked audit log.

Every scope decision, tool call, confirmation and agent lifecycle event is
recorded. Each entry commits to the previous entry's hash, so silent
tampering (removing/reordering entries) is detectable via verify_chain().
"""

from __future__ import annotations

import hashlib
import json
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .redact import redactor

GENESIS = "0" * 64


def _canonical(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _entry_hash(prev_hash: str, payload: dict) -> str:
    return hashlib.sha256((prev_hash + _canonical(payload)).encode("utf-8")).hexdigest()


class AuditLog:
    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._seq = 0
        self._prev_hash = GENESIS
        if self.path.exists():
            self._resume()

    def _resume(self) -> None:
        """Continue an existing chain instead of starting a new file."""
        last = None
        for line in self.path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line:
                try:
                    last = json.loads(line)
                except json.JSONDecodeError:
                    continue
        if last:
            self._prev_hash = last.get("hash", GENESIS)
            self._seq = int(last.get("seq", 0))

    def record(
        self,
        event: str,
        actor: str = "",
        tool: str = "",
        target: str = "",
        decision: str = "",
        detail: dict[str, Any] | None = None,
    ) -> dict:
        with self._lock:
            self._seq += 1
            payload = {
                "ts": datetime.now(timezone.utc).isoformat(),
                "seq": self._seq,
                "event": event,
                "actor": actor,
                "tool": tool,
                "target": redactor.scrub(target),
                "decision": redactor.scrub(decision),
                "detail": redactor.scrub_obj(detail or {}),
                "prev_hash": self._prev_hash,
            }
            digest = _entry_hash(self._prev_hash, payload)
            entry = {**payload, "hash": digest}
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(_canonical(entry) + "\n")
            self._prev_hash = digest
            return entry


def verify_chain(path: str | Path) -> tuple[bool, str]:
    """Recompute the hash chain. Returns (ok, message)."""
    prev = GENESIS
    count = 0
    for lineno, line in enumerate(Path(path).read_text(encoding="utf-8").splitlines(), 1):
        line = line.strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError as exc:
            return False, f"line {lineno}: invalid JSON ({exc})"
        stored = entry.pop("hash", "")
        if entry.get("prev_hash") != prev:
            return False, f"line {lineno}: prev_hash broken (chain tampered or reordered)"
        if _entry_hash(entry.get("prev_hash", GENESIS), entry) != stored:
            return False, f"line {lineno}: entry hash mismatch (content modified)"
        prev = stored
        count += 1
    return True, f"chain intact: {count} entries"
