"""Phase 1.3 — deterministic triage: root-cause dedup clustering and
evidence standards. Runs on the finding STORE, not via the LLM: the same
logic applies whether a human, the analyst agent, or a replay wrote a
finding, and the reporter cannot route around it.

Honesty rules baked in:
- cross-host merging is deliberately NOT done (see cluster_findings); the
  report never implies a finding's blast radius is smaller than it is.
- a finding whose evidence looks unsupported is DOWNGRADED to suspected,
  never silently deleted — the caveat stays visible in the report.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field, replace
from urllib.parse import urlsplit

from .state import Finding, evidence_supported

__all__ = [
    "Cluster",
    "apply_evidence_standards",
    "cluster_findings",
    "evidence_supported",
]

_TITLE_NOISE = re.compile(
    r"\b(the|a|an|is|are|of|on|for|to|in|at|and|or|with|found|detected)\b",
    re.IGNORECASE,
)


def _norm_title(title: str) -> str:
    """Aggressive title normalization for grouping (NOT for display).

    Token ORDER is discarded: 'Missing HSTS header' and 'HSTS header is
    missing' are the same root cause. The CWE in the cluster key keeps
    different issue classes with similar wording apart.
    """
    t = _TITLE_NOISE.sub("", title.lower())
    t = re.sub(r"[^a-z0-9]+", " ", t)
    return " ".join(sorted(t.split()))


def _host(url: str) -> str:
    """Lowercased host[:port] of a URL (or the bare target).

    Host IS part of the cluster key: two hosts with a 'missing HSTS' finding
    are two distinct blast-radius facts and merging them would misrepresent
    scope. Port is kept — different ports are different services.
    """
    if "://" in url:
        return urlsplit(url).netloc.lower()
    return url.split("/")[0].strip().lower()


def _root_key(f: Finding) -> tuple[str, str, str]:
    """Cluster key: (normalized title, cwe, host).

    Path and query are deliberately EXCLUDED from the key: one misconfiguration
    manifesting on 40 URLs of one host is ONE root cause with 40 instances
    (roadmap 1.3). Every instance URL is still listed individually, so no
    per-URL visibility is lost. A different title or a different CWE is a
    different root cause and never merges.
    """
    return (_norm_title(f.title), f.cwe.strip().lower(), _host(f.target))


@dataclass
class Cluster:
    finding: Finding
    instance_targets: list[str] = field(default_factory=list)
    confirmed_targets: list[str] = field(default_factory=list)

    @property
    def confirmed_on_all(self) -> bool:
        return (len(self.confirmed_targets) == len(self.instance_targets)
                and bool(self.instance_targets))


def apply_evidence_standards(findings: list[Finding]) -> list[Finding]:
    """Downgrade 'confirmed' findings whose evidence lacks a response
    artifact. Returns new Finding objects; input list untouched."""
    out: list[Finding] = []
    for f in findings:
        if f.status == "confirmed" and not evidence_supported(f):
            out.append(replace(
                f,
                status="suspected",
                evidence=(f.evidence + "\n[evidence-standard] downgraded to "
                          "suspected: no tool-observed response in evidence"),
            ))
        else:
            out.append(f)
    return out


def cluster_findings(findings: list[Finding]) -> list[Cluster]:
    """Group same-root-cause findings (see _root_key) into clusters.

    Reduce rules (deterministic, no LLM):
    - severity: max across members;
    - status: 'confirmed' iff at least one instance was demonstrated — the
      evidence standard already guarantees each confirmed member carries a
      response pair, and confirmed_targets records WHICH instances were
      demonstrated so the report can disclose 'confirmed on k of N URLs';
      when the cluster is confirmed, displayed evidence comes from a
      confirmed member (it is the evidence that supports the status);
    - taxonomy/remediation/tool: from the highest-severity member
      (ties: first recorded);
    - every distinct target URL is kept as an instance. Cross-host findings
      never merge (see _root_key).
    """
    sev_rank = {s: i for i, s in enumerate(
        ("critical", "high", "medium", "low", "info"))}
    groups: dict[tuple[str, str, str], list[Finding]] = {}
    for f in findings:
        groups.setdefault(_root_key(f), []).append(f)

    clusters: list[Cluster] = []
    for members in groups.values():
        best = min(members, key=lambda m: sev_rank.get(m.severity, 99))
        confirmed_members = [m for m in members if m.status == "confirmed"]
        instance_targets = list(dict.fromkeys(m.target for m in members))
        confirmed_targets = list(dict.fromkeys(m.target for m in confirmed_members))
        if confirmed_members:
            # displayed evidence must support the displayed status: prefer a
            # confirmed member's response-pair evidence, best severity first
            evidence_src = min(confirmed_members,
                               key=lambda m: sev_rank.get(m.severity, 99))
            status = "confirmed"
        else:
            evidence_src = best
            status = "suspected"
        rep = replace(best, status=status, evidence=evidence_src.evidence)
        if len(confirmed_targets) < len(instance_targets):
            # honest partial confirmation stays visible on the finding itself
            rep = replace(rep, evidence=(
                rep.evidence
                + f"\n[coverage] demonstrated on {len(confirmed_targets)} of "
                f"{len(instance_targets)} listed URL(s); the other(s) share "
                "the same root cause but were not individually confirmed"
            ).strip())
        clusters.append(Cluster(finding=rep, instance_targets=instance_targets,
                                confirmed_targets=confirmed_targets))
    return clusters
