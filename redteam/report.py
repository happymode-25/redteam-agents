"""Markdown report rendering: structured findings + agent narrative."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Collection

from .coverage import render_coverage
from .drift import fingerprint
from .redact import redactor
from .review import apply_reviews
from .state import SEVERITIES, SharedState
from .triage import apply_evidence_standards, cluster_findings

SEVERITY_BADGE = {
    "critical": "CRITICAL",
    "high": "HIGH",
    "medium": "MEDIUM",
    "low": "LOW",
    "info": "INFO",
}


def render_report(target: str, narrative: str, state: SharedState,
                  identities: bool = False,
                  tools_used: Collection[str] = (),
                  usage: str = "",
                  drift_md: str = "",
                  reviews: dict[str, dict] | None = None) -> str:
    """Render the markdown report.

    usage:    estimated LLM usage line (Phase 4 cost governance footer);
    drift_md: pre-rendered "Drift Since Last Run" section from drift.py;
    reviews:  human review decisions keyed by finding fingerprint — applied
              to the reported status and printed with reviewer/note.
    """
    reviews = reviews or {}
    # Phase 1.3: enforce evidence standards, then cluster by root cause so
    # one misconfig across N URLs is reported once (with N instances).
    vetted = apply_evidence_standards(state.sorted_findings())
    vetted = apply_reviews(vetted, reviews)
    clusters = cluster_findings(vetted)
    findings = [c.finding for c in clusters]
    counts = {s: sum(1 for f in findings if f.severity == s) for s in SEVERITIES}
    total_instances = sum(len(c.instance_targets) for c in clusters)

    lines: list[str] = []
    lines.append(f"# Red Team Assessment Report — `{target}`")
    lines.append("")
    lines.append(f"- **Generated:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}")
    lines.append(f"- **Findings:** {len(findings)} distinct "
                 f"(critical: {counts['critical']}, high: {counts['high']}, "
                 f"medium: {counts['medium']}, low: {counts['low']}, info: {counts['info']}) "
                 f"across {total_instances} affected URL(s)")
    lines.append("- **Authorization:** autonomous assessment executed against a "
                 "pre-authorized scope allowlist")
    lines.append("")

    if narrative.strip():
        lines.append("## Agent Narrative")
        lines.append("")
        lines.append(narrative.strip())
        lines.append("")

    lines.append("## Findings Summary")
    lines.append("")
    if not findings:
        lines.append("No findings were recorded during this assessment.")
        lines.append("")
    else:
        lines.append("| ID | Severity | Status | Title | Affected |")
        lines.append("|----|----------|--------|-------|----------|")
        for cl in clusters:
            f = cl.finding
            n = len(cl.instance_targets)
            affected = f"`{f.target}`" if n <= 1 else f"{n} URLs"
            lines.append(
                f"| {f.id} | {SEVERITY_BADGE.get(f.severity, f.severity.upper())} "
                f"| {f.status} | {f.title} | {affected} |"
            )
        lines.append("")

        if drift_md.strip():
            lines.append(drift_md.strip())
            lines.append("")

        lines.append("## Findings Detail")
        lines.append("")
        for cl in clusters:
            f = cl.finding
            lines.append(f"### {f.id} — {f.title} "
                         f"[{SEVERITY_BADGE.get(f.severity, f.severity.upper())} / {f.status}]")
            lines.append("")
            lines.append(f"- **Target:** `{f.target}`")
            if len(cl.instance_targets) > 1:
                lines.append(f"- **Same root cause on {len(cl.instance_targets)} URL(s):**")
                for t in cl.instance_targets:
                    mark = " ✓demonstrated" if t in cl.confirmed_targets else ""
                    lines.append(f"  - `{t}`{mark}")
                if cl.confirmed_targets and not cl.confirmed_on_all:
                    lines.append(f"- **Evidence demonstrates this issue on "
                                 f"{len(cl.confirmed_targets)} of "
                                 f"{len(cl.instance_targets)} URL(s)** — the "
                                 "others share the root cause but were not "
                                 "individually confirmed.")
            if f.tool:
                lines.append(f"- **Discovered by:** {f.tool}")
            taxonomy = ", ".join(
                part for part in (
                    f"CWE: {f.cwe}" if f.cwe else "",
                    f"CVSS: {f.cvss}" if f.cvss else "",
                    f"CVE: {f.cves}" if f.cves else "",
                ) if part
            )
            if taxonomy:
                lines.append(f"- **Classification:** {taxonomy}")
            lines.append(f"- **Recorded:** {f.created_at}")
            review = reviews.get(fingerprint(f))
            if review:
                who = review.get("reviewer") or "operator"
                note = f" — {review['note']}" if review.get("note") else ""
                lines.append(f"- **Human review:** {review.get('status', '')} "
                             f"by {who}{note}")
            lines.append("")
            if f.evidence:
                lines.append("**Evidence:**")
                lines.append("")
                lines.append("```")
                lines.append(f.evidence)
                lines.append("```")
                lines.append("")
            if f.remediation:
                lines.append(f"**Remediation:** {f.remediation}")
                lines.append("")

    lines.append("---")
    lines.append("")
    lines.append(render_coverage(identities=identities, tools_used=tools_used))
    lines.append("---")
    lines.append("")
    if usage.strip():
        lines.append(f"*{usage.strip()}*")
        lines.append("")
    lines.append("*Generated by redteam-agents. Verify every finding manually before "
                 "acting on it — autonomous assessments can be wrong.*")
    lines.append("")
    # defense in depth: the whole rendered document passes the redaction net
    return redactor.scrub("\n".join(lines))
