"""Credential redaction pass (Phase 2.1).

Operator identity secrets (passwords, session cookies, API tokens) are
resolved from environment variables at login time and registered here.
Every output channel that could carry them back out — audit log entries,
finding evidence, the rendered report — scrubs registered secrets first.

Leaf module: imports nothing from redteam, so anything may import it.

Honesty note: this is a containment net, not a sandbox. It catches the
realistic leak paths (login error messages echoing credentials, tokens
reflected in responses, copy-pasted evidence). It cannot catch a target
server storing our password somewhere we later read, and it never scrubs
TARGET secrets found during testing (those are findings — we only redact
what WE brought).
"""

from __future__ import annotations

import threading

REDACTED = "[REDACTED]"
# Secrets shorter than this are too generic to blind-replace in text
# (e.g. a 3-char value would mangle unrelated prose).
MIN_SECRET_LEN = 6


class Redactor:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._secrets: set[str] = set()

    def register(self, secret: str | None) -> None:
        """Register a secret value for scrubbing. None/short values ignored."""
        if not secret:
            return
        s = str(secret)
        if len(s) < MIN_SECRET_LEN:
            return
        with self._lock:
            self._secrets.add(s)

    def scrub(self, text: str) -> str:
        """Replace every registered secret appearing in text with [REDACTED]."""
        if not text:
            return text
        with self._lock:
            secrets = sorted(self._secrets, key=len, reverse=True)  # longest first
        out = str(text)
        for s in secrets:
            if s in out:
                out = out.replace(s, REDACTED)
        return out

    def scrub_obj(self, obj):
        """Deep-scrub strings inside dicts/lists (audit details)."""
        if isinstance(obj, str):
            return self.scrub(obj)
        if isinstance(obj, dict):
            return {k: self.scrub_obj(v) for k, v in obj.items()}
        if isinstance(obj, list):
            return [self.scrub_obj(v) for v in obj]
        return obj

    @property
    def count(self) -> int:
        with self._lock:
            return len(self._secrets)

    def clear(self) -> None:
        """Test helper — drops all registered secrets."""
        with self._lock:
            self._secrets.clear()


# Process-wide instance: registered at login, applied at every exit point.
redactor = Redactor()
