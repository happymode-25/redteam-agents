"""Shared state: findings and per-stage notes flowing between agents."""

from __future__ import annotations

import json
import threading
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path

from .redact import redactor

SEVERITIES = ("critical", "high", "medium", "low", "info")

# Evidence standard (Phase 1.3): a 'confirmed' finding must show a
# tool-observed response, not just a claim. We look for at least one HTTP
# response artifact in the evidence text.
_RESPONSE_MARKERS = (
    "http/1.", "http/2", "http/3", "http/0.9",   # response status line
    "status", " <- ", " <= ", " => ", " -> ",    # request->response pairs
    "< ", "resp:", "response:",
)


def evidence_supported(f: "Finding") -> bool:
    """True when the evidence text plausibly contains a tool-observed
    response (request/response pair), as required for 'confirmed'."""
    ev = (f.evidence or "").strip().lower()
    if len(ev) < 12:
        return False
    return any(marker in ev for marker in _RESPONSE_MARKERS)


def normalize_severity(value: str | None) -> str:
    v = (value or "info").strip().lower()
    if v in SEVERITIES:
        return v
    # nuclei-style composite severities, e.g. "critical,high"
    for sev in SEVERITIES:
        if sev in v:
            return sev
    return "info"


@dataclass
class Finding:
    id: str
    title: str
    severity: str
    target: str
    evidence: str = ""
    remediation: str = ""
    tool: str = ""
    status: str = "suspected"  # suspected | confirmed
    cwe: str = ""
    cvss: str = ""
    cves: str = ""
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def key(self) -> tuple[str, str]:
        return (self.title.strip().lower(), self.target.strip().lower())


class SharedState:
    """Thread-safe store the orchestrator and all agents share."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.findings: list[Finding] = []
        self.notes: dict[str, str] = {}  # stage name -> agent summary
        self._counter = 0

    def add_finding(
        self,
        title: str,
        severity: str,
        target: str,
        evidence: str = "",
        remediation: str = "",
        tool: str = "",
        status: str = "suspected",
        cwe: str = "",
        cvss: str = "",
        cves: str = "",
    ) -> Finding:
        with self._lock:
            self._counter += 1
            # credential redaction: our identity secrets never persist in
            # findings (target-found secrets are findings, not ours)
            title = redactor.scrub(str(title))
            target = redactor.scrub(str(target))
            evidence = redactor.scrub(str(evidence))
            remediation = redactor.scrub(str(remediation))
            probe = Finding(
                id="_probe", title=title, severity="info", target=target,
                evidence=evidence, status=status,
            )
            # Evidence standard, enforced for every writer (agent tool,
            # replay, or code): confirmed needs a tool-observed response.
            if status == "confirmed" and not evidence_supported(probe):
                status = "suspected"
                evidence = (evidence + "\n[evidence-standard] recorded as "
                            "suspected: evidence lacked a tool-observed "
                            "response").strip()
            finding = Finding(
                id=f"F{self._counter:03d}",
                title=title,
                severity=normalize_severity(severity),
                target=target,
                evidence=evidence[:4000],
                remediation=remediation[:2000],
                tool=tool,
                status=status if status in ("suspected", "confirmed") else "suspected",
                cwe=str(cwe)[:200],
                cvss=str(cvss)[:50],
                cves=str(cves)[:500],
            )
            existing = {f.key() for f in self.findings}
            if finding.key() in existing:
                return next(f for f in self.findings if f.key() == finding.key())
            self.findings.append(finding)
            return finding

    def set_note(self, stage: str, text: str) -> None:
        with self._lock:
            self.notes[stage] = text

    def get_note(self, stage: str) -> str:
        with self._lock:
            return self.notes.get(stage, "")

    def sorted_findings(self) -> list[Finding]:
        order = {s: i for i, s in enumerate(SEVERITIES)}
        with self._lock:
            return sorted(self.findings, key=lambda f: order.get(f.severity, 99))

    def to_dict(self) -> dict:
        with self._lock:
            return {
                "findings": [asdict(f) for f in self.findings],
                "notes": dict(self.notes),
            }

    def save(self, path: str | Path) -> None:
        Path(path).write_text(
            json.dumps(self.to_dict(), indent=2, ensure_ascii=False), encoding="utf-8"
        )
