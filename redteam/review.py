"""Human review queue for findings (Phase 4).

Autonomous findings are candidates, not verdicts. An operator reviews each
one and records a decision keyed by the stable finding fingerprint:

  confirmed       — reproduced/verified by a human (status becomes confirmed)
  false_positive  — investigated and wrong (status becomes false_positive)
  accepted_risk   — real, but accepted by the customer (accepted_risk)
  needs_info      — more data required; finding stays suspected

Decisions live in a JSON file (artifacts/reviews.json by default), survive
re-runs, and are applied at report time. The fingerprints match drift and
ticket dedup keys, so one identifier follows a finding through its whole
lifecycle.

Wording matters: a review decision is a HUMAN statement. This module never
invents one, and the report prints the reviewer + note next to the status.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

from .drift import fingerprint
from .state import Finding

STATUSES = ("confirmed", "false_positive", "accepted_risk", "needs_info")
# statuses that replace the finding's reported status
_APPLIED = {"confirmed": "confirmed", "false_positive": "false_positive",
            "accepted_risk": "accepted_risk"}


def load_reviews(path: str | Path) -> dict[str, dict]:
    p = Path(path)
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    reviews = data.get("reviews", data) if isinstance(data, dict) else {}
    return {str(k): v for k, v in reviews.items() if isinstance(v, dict)}


def save_reviews(path: str | Path, reviews: dict[str, dict]) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps({"reviews": reviews}, indent=2, ensure_ascii=False),
                 encoding="utf-8")


def set_review(path: str | Path, fp: str, status: str, note: str = "",
               reviewer: str = "") -> dict:
    status = status.strip().lower()
    if status not in STATUSES:
        raise ValueError(f"review status must be one of {STATUSES}, got {status!r}")
    reviews = load_reviews(path)
    entry = {
        "status": status,
        "note": note,
        "reviewer": reviewer,
        "ts": datetime.now(timezone.utc).isoformat(),
    }
    reviews[fp] = entry
    save_reviews(path, reviews)
    return entry


def apply_reviews(findings: Iterable[Finding],
                  reviews: dict[str, dict]) -> list[Finding]:
    """Return copies with human decisions applied (originals untouched)."""
    out: list[Finding] = []
    for f in findings:
        item = replace(f)
        review = reviews.get(fingerprint(f))
        if review:
            mapped = _APPLIED.get(str(review.get("status", "")))
            if mapped:
                item.status = mapped
        out.append(item)
    return out


def render_finding_table(findings: Iterable[Finding]) -> str:
    lines = ["| Fingerprint | ID | Severity | Status | Title |",
             "|---|---|---|---|---|"]
    for f in findings:
        lines.append(f"| `{fingerprint(f)}` | {f.id} | {f.severity} "
                     f"| {f.status} | {f.title} |")
    return "\n".join(lines)


def render_review_table(reviews: dict[str, dict]) -> str:
    if not reviews:
        return "(no review decisions recorded)"
    lines = ["| Fingerprint | Status | Reviewer | Note |", "|---|---|---|---|"]
    for fp, entry in sorted(reviews.items()):
        lines.append(f"| `{fp}` | {entry.get('status', '')} "
                     f"| {entry.get('reviewer', '')} "
                     f"| {entry.get('note', '')} |")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Review/triage findings by fingerprint")
    parser.add_argument("--findings", default="",
                        help="findings JSON (for --list)")
    parser.add_argument("--reviews", default="artifacts/reviews.json")
    parser.add_argument("--list", action="store_true", default=False,
                        help="list findings with fingerprints and current status")
    parser.add_argument("--set", metavar="FINGERPRINT", default="",
                        help="fingerprint to review")
    parser.add_argument("--status", default="",
                        choices=["", *STATUSES])
    parser.add_argument("--note", default="")
    parser.add_argument("--reviewer", default="")
    parser.add_argument("--show", action="store_true",
                        help="show recorded review decisions")
    args = parser.parse_args(argv)

    if args.set:
        if not args.status:
            print("--set requires --status", file=sys.stderr)
            return 2
        try:
            entry = set_review(args.reviews, args.set, args.status,
                               note=args.note, reviewer=args.reviewer)
        except ValueError as exc:
            print(f"Review error: {exc}", file=sys.stderr)
            return 1
        print(f"recorded {args.set} -> {entry['status']}")
        return 0

    reviews = load_reviews(args.reviews)
    if args.show or not args.findings:
        print(render_review_table(reviews))
        return 0

    from .tickets import load_findings  # reuse the JSON reader

    findings = apply_reviews(load_findings(args.findings), reviews)
    print(render_finding_table(findings))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
