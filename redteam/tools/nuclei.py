"""nuclei template scan wrapper (JSONL output parsed into findings).

Phase 1.2: the scan policy is enforced in CODE, not by prompt —
- severity floor (requests below it fail loudly instead of scanning more),
- tag universe (agents propose, code curates; 'dos' is never allowed —
  catalog section 22 is permanently excluded),
- template pinning (refuses to scan when HEAD != reviewed commit),
- no auto-update checks (`-duc`), update policy is manual-only.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

from ..config import SEVERITIES, NucleiConfig
from .base import Tool, ToolError, ToolResult

# hard policy: never scanned, not overridable via config include lists
HARD_EXCLUDED_TAGS = frozenset({"dos"})


def clamp_severity(requested: str | None, floor: str) -> str:
    """Effective severity filter: requested ∩ [floor..critical].

    - requested empty -> everything from the floor up
    - request entirely below the floor -> ToolError (do NOT silently widen)
    """
    floor_idx = SEVERITIES.index(floor)
    # SEVERITIES is ordered critical..info (descending); "at or above the
    # floor" means index <= floor_idx.
    allowed = [s for s in SEVERITIES if SEVERITIES.index(s) <= floor_idx]
    if not requested:
        return ",".join(allowed)
    req = [s.strip().lower() for s in str(requested).split(",") if s.strip()]
    unknown = [s for s in req if s not in SEVERITIES]
    if unknown:
        raise ToolError(f"unknown severity value(s): {unknown}; valid: {list(SEVERITIES)}")
    effective = [s for s in allowed if s in req]
    if not effective:
        raise ToolError(
            f"requested severities {req} are all below the configured floor "
            f"'{floor}' — nothing to scan; ask for {allowed} or lower the floor "
            "in config (operator decision)"
        )
    return ",".join(effective)


def curate_tags(requested: str | None, cfg: NucleiConfig) -> tuple[list[str], list[str]]:
    """Filter requested tags through the policy.

    Returns (effective, dropped). dropped is reported in the tool summary so
    the agent and the report know what policy removed.
    """
    req = [t.strip().lower() for t in str(requested or "").split(",") if t.strip()]
    universe = set(cfg.tags_include) if cfg.tags_include else None
    excluded = {t.strip().lower() for t in cfg.tags_exclude} | HARD_EXCLUDED_TAGS
    effective: list[str] = []
    dropped: list[str] = []
    for t in req:
        if t in excluded:
            dropped.append(t)
        elif universe is not None and t not in universe:
            dropped.append(t)
        elif t in effective:
            continue
        else:
            effective.append(t)
    return effective, dropped


def build_nuclei_args(
    target: str,
    cfg: NucleiConfig,
    severity: str,
    tags: list[str],
    template_dir: str | None,
) -> list[str]:
    cmd = ["nuclei", "-jsonl", "-silent", "-timeout", "10", "-duc"]
    if "://" in target:
        cmd += ["-u", target]
    else:
        cmd += ["-target", target]
    if severity:
        cmd += ["-severity", severity]
    if tags:
        cmd += ["-tags", ",".join(tags)]
    excludes = sorted({t.strip().lower() for t in cfg.tags_exclude if t.strip()}
                      | HARD_EXCLUDED_TAGS)
    if excludes:
        cmd += ["-exclude-tags", ",".join(excludes)]
    if template_dir:
        cmd += ["-t", template_dir]
    return cmd


def resolve_template_pin(cfg: NucleiConfig) -> tuple[str | None, str]:
    """Return (template_dir_for_-t, pin_note); raise ToolError on pin mismatch.

    git runs host-side (this is a local provenance check, not target traffic),
    so it deliberately uses subprocess, not the tool runner.
    """
    if not cfg.template_dir:
        return None, "default template set (UNPINNED — set nuclei.template_dir + expected_commit)"
    p = Path(cfg.template_dir)
    if not p.is_dir():
        raise ToolError(f"nuclei.template_dir not found: {p}")
    if not cfg.expected_commit:
        return str(p), f"templates at {p} (no expected_commit — pin not enforced)"
    proc = subprocess.run(
        ["git", "-C", str(p), "rev-parse", "HEAD"],
        capture_output=True, text=True, timeout=30,
    )
    if proc.returncode != 0:
        raise ToolError(
            f"template_dir is not a git checkout, cannot verify pin: {p}"
        )
    head = proc.stdout.strip()
    expected = cfg.expected_commit.strip()
    if not (head.startswith(expected) or expected.startswith(head)):
        raise ToolError(
            f"template pin mismatch: HEAD={head[:12]} expected={expected[:12]} — "
            "review the template diff, then update nuclei.expected_commit "
            "(update_policy: manual)"
        )
    return str(p), f"pinned templates @ {head[:12]}"


class NucleiTool(Tool):
    name = "nuclei_scan"
    description = (
        "Template-based vulnerability scan with Nuclei against an authorized URL "
        "or host. Returns matched templates as structured findings with severity, "
        "evidence and remediation guidance. Severity floor and tag policy are "
        "enforced in code; the result reports any tags policy dropped."
    )
    binary = "nuclei"
    parameters = {
        "type": "object",
        "properties": {
            "target": {
                "type": "string",
                "description": "URL or host to scan (must be in scope)",
            },
            "severity": {
                "type": "string",
                "description": "Comma-separated severity filter: critical,high,medium,low,info "
                               "(clamped to the configured floor)",
            },
            "tags": {
                "type": "string",
                "description": "Comma-separated template tags to include, e.g. 'cve,xss' "
                               "(filtered through the configured tag universe)",
            },
        },
        "required": ["target"],
    }

    def __init__(self, cfg: NucleiConfig | None = None):
        self.cfg = cfg or NucleiConfig()

    def run(self, args: dict[str, Any]) -> ToolResult:
        target = str(args["target"])
        severity = clamp_severity(args.get("severity"), self.cfg.severity_floor)
        tags, dropped = curate_tags(args.get("tags"), self.cfg)
        if args.get("tags") and not tags:
            raise ToolError(
                f"all requested tags were dropped by policy: {dropped}"
            )
        template_dir, pin_note = resolve_template_pin(self.cfg)
        cmd = build_nuclei_args(target, self.cfg, severity, tags, template_dir)

        proc = self.shell(cmd, timeout=1800)
        stdout = proc.stdout.strip()
        if not stdout:
            if proc.returncode not in (0, 1):
                raise ToolError(f"nuclei failed (rc={proc.returncode}): {proc.stderr[:300]}")
            summary = f"nuclei found no matching vulnerabilities [{pin_note}]"
            if dropped:
                summary += f"; policy dropped tags: {','.join(dropped)}"
            return ToolResult(
                ok=True,
                summary=summary,
                data={"policy": {"severity": severity, "tags": tags,
                                 "dropped_tags": dropped, "template_pin": pin_note}},
            )

        matches: list[dict[str, Any]] = []
        for line in stdout.splitlines():
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            info = event.get("info") or {}
            classification = event.get("classification") or info.get("classification") or {}
            cwe = classification.get("cwe-id") or info.get("cwe-id") or ""
            cvss = classification.get("cvss") or info.get("cvss") or ""
            cves = classification.get("cve-id") or info.get("cve-id") or ""
            if isinstance(cwe, list):
                cwe = ",".join(str(c) for c in cwe)
            if isinstance(cves, list):
                cves = ",".join(str(c) for c in cves)
            matches.append(
                {
                    "template_id": event.get("template-id") or event.get("templateID"),
                    "name": info.get("name"),
                    "severity": info.get("severity", "info"),
                    "matched_at": event.get("matched-at") or event.get("matched"),
                    "description": (info.get("description") or "")[:500],
                    "remediation": (info.get("remediation") or "")[:500],
                    "cwe": str(cwe)[:200],
                    "cvss": str(cvss)[:50],
                    "cves": str(cves)[:500],
                    "extracted": [str(x)[:200] for x in (event.get("extracted-results") or [])[:5]],
                }
            )

        summary = f"nuclei matched {len(matches)} template(s) [{pin_note}]"
        if dropped:
            summary += f"; policy dropped tags: {','.join(dropped)}"
        return ToolResult(
            ok=True,
            summary=summary,
            data={
                "matches": matches,
                "policy": {"severity": severity, "tags": tags,
                           "dropped_tags": dropped, "template_pin": pin_note},
            },
            raw=stdout,
        )
