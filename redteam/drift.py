"""Drift detection between consecutive runs against the same target (Phase 4).

A scheduled scan is only useful if it tells the operator what CHANGED. Each
run writes a normalized findings snapshot next to its report; the next run
diffs against it and the report gains a "Drift since last run" section:

  * NEW        â€” findings this run that the previous snapshot did not have;
  * RESOLVED   â€” previously reported findings that no longer appear
                 (fixed, or a scanner/tool gap â€” the report says which
                 possibility cannot be excluded);
  * PERSISTING â€” same finding in both runs.

Identity is a stable fingerprint over (title, target, CWE) â€” NOT over
severity/status/evidence, so a re-worded evidence line or a severity
re-rating does not masquerade as a new finding. Fingerprints are also the
dedup keys used by review decisions and ticket export, so one identifier
follows a finding through its whole lifecycle.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from .state import Finding


def fingerprint(finding: Finding) -> str:
    """Stable identity: title + target + CWE (normalized). 16 hex chars."""
    raw = "|".join((
        re.sub(r"\s+", " ", (finding.title or "")).strip().lower(),
        (finding.target or "").strip().lower(),
        re.sub(r"\s+", "", (finding.cwe or "")).upper(),
    ))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def target_slug(target: str) -> str:
    slug = re.sub(r"[^a-zA-Z0-9._-]+", "-", target or "target").strip("-")
    return (slug or "target")[:80]


def snapshot(target: str, findings: Iterable[Finding]) -> dict[str, Any]:
    items = []
    for f in findings:
        items.append({
            "fingerprint": fingerprint(f),
            "id": f.id,
            "title": f.title,
            "severity": f.severity,
            "status": f.status,
            "target": f.target,
            "cwe": f.cwe,
        })
    return {
        "target": target,
        "ts": datetime.now(timezone.utc).isoformat(),
        "findings": items,
    }


def snapshot_path(artifacts_dir: str | Path, target: str) -> Path:
    return Path(artifacts_dir) / "state" / f"findings-{target_slug(target)}.json"


def load_snapshot(path: str | Path) -> dict[str, Any] | None:
    p = Path(path)
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(data, dict) or not isinstance(data.get("findings"), list):
        return None
    return data


def save_snapshot(path: str | Path, data: dict[str, Any]) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")


@dataclass
class Drift:
    new: list[dict[str, Any]]
    resolved: list[dict[str, Any]]
    persisting: list[dict[str, Any]]
    first_run: bool = False

    @property
    def counts(self) -> dict[str, int]:
        return {"new": len(self.new), "resolved": len(self.resolved),
                "persisting": len(self.persisting)}


def compare(previous: dict[str, Any] | None,
            current: dict[str, Any]) -> Drift:
    """Diff snapshots by fingerprint. Missing previous = first run."""
    if not previous:
        items = list(current.get("findings", []))
        return Drift(new=items, resolved=[], persisting=[], first_run=True)
    prev_by_fp = {item.get("fingerprint"): item
                  for item in previous.get("findings", []) if item.get("fingerprint")}
    cur_by_fp = {item.get("fingerprint"): item
                 for item in current.get("findings", []) if item.get("fingerprint")}
    new = [item for fp, item in cur_by_fp.items() if fp not in prev_by_fp]
    resolved = [item for fp, item in prev_by_fp.items() if fp not in cur_by_fp]
    persisting = [item for fp, item in cur_by_fp.items() if fp in prev_by_fp]
    new.sort(key=lambda i: (i.get("severity", ""), i.get("title", "")))
    resolved.sort(key=lambda i: (i.get("severity", ""), i.get("title", "")))
    persisting.sort(key=lambda i: (i.get("severity", ""), i.get("title", "")))
    return Drift(new=new, resolved=resolved, persisting=persisting)


def render_drift_markdown(drift: Drift,
                          previous_ts: str | None = None) -> str:
    """Human-readable drift section. Never overstates a resolved finding."""
    if drift.first_run:
        return ("## Drift Since Last Run\n\n"
                "First recorded run for this target â€” no previous snapshot to "
                "compare against. The next run will report new/resolved/"
                "persisting findings.\n")
    counts = drift.counts
    lines = [
        "## Drift Since Last Run",
        "",
        f"- **Previous snapshot:** {previous_ts or 'unknown'}",
        f"- **New:** {counts['new']} Â· **Persisting:** {counts['persisting']} "
        f"Â· **Resolved:** {counts['resolved']}",
        "",
    ]
    if drift.new:
        lines.append("**New findings:**")
        lines.append("")
        for item in drift.new:
            lines.append(f"- `{item.get('fingerprint')}` "
                         f"[{item.get('severity', 'info')}] {item.get('title')} "
                         f"(`{item.get('target')}`)")
        lines.append("")
    if drift.resolved:
        lines.append("**Resolved since last run** (absent this run â€” fixed, or "
                     "the check that found it did not run; verify before "
                     "closing):")
        lines.append("")
        for item in drift.resolved:
            lines.append(f"- `{item.get('fingerprint')}` "
                         f"[{item.get('severity', 'info')}] {item.get('title')} "
                         f"(`{item.get('target')}`)")
        lines.append("")
    if drift.persisting:
        lines.append("**Persisting:**")
        lines.append("")
        for item in drift.persisting:
            lines.append(f"- `{item.get('fingerprint')}` "
                         f"[{item.get('severity', 'info')}] {item.get('title')}")
        lines.append("")
    return "\n".join(lines)

