"""Engagement model (Phase 4): customer → engagement → scope + authorization.

An engagement file binds a piece of work to its authorization evidence:

    engagement:
      id: ACME-2026-01
      customer: ACME Corp
      operator: alice
      authorization_letter: letters/acme-signed.pdf   # any file; hash recorded
      window: {start: 2026-10-01, end: 2026-10-31}
      scope:
        allow_domains: [acme-example.com]
        allow_cidrs: ["203.0.113.0/24"]
        allow_private: false

Loading is fail-closed:
  * the letter must EXIST and be non-empty — its SHA-256 is recorded in the
    audit log, so the exact authorization document a run claims is fixed;
  * the assessment window must cover today (both bounds optional);
  * the scope must name at least one allowed domain or CIDR — an engagement
    with no scope authorizes nothing.

The engagement REPLACES the config scope (engagement files are more specific
than a general config), and the load event is auditable end to end.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, replace
from datetime import date, datetime
from pathlib import Path

import yaml

from .config import AppConfig


@dataclass
class Engagement:
    id: str
    customer: str
    operator: str
    letter_path: str
    letter_sha256: str
    window_start: str          # "" = open start
    window_end: str            # "" = open end
    allow_domains: tuple[str, ...]
    allow_cidrs: tuple[str, ...]
    allow_subdomains: bool
    allow_private: bool
    raw_path: str

    def describe(self) -> str:
        window = f"{self.window_start or 'open'}..{self.window_end or 'open'}"
        letter = f"{Path(self.letter_path).name} ({self.letter_sha256[:12]}…)"
        return (f"{self.id} — {self.customer}; window {window}; "
                f"authorization {letter}")


def _iso_date(value: str, field: str) -> str:
    try:
        date.fromisoformat(value)
    except ValueError as exc:
        raise ValueError(
            f"engagement window.{field} must be an ISO date (YYYY-MM-DD), "
            f"got {value!r}") from exc
    return value


def load_engagement(path: str | Path, now: date | None = None) -> Engagement:
    p = Path(path)
    if not p.exists():
        raise ValueError(f"engagement file not found: {p}")
    try:
        data = yaml.safe_load(p.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise ValueError(f"engagement file is not valid YAML: {exc}") from exc
    if not isinstance(data, dict):
        raise ValueError("engagement file must be a YAML mapping")
    eng = data.get("engagement", data)
    if not isinstance(eng, dict):
        raise ValueError("engagement file must contain an 'engagement' mapping")

    eid = str(eng.get("id", "")).strip()
    customer = str(eng.get("customer", "")).strip()
    if not eid:
        raise ValueError("engagement.id is required")
    if not customer:
        raise ValueError("engagement.customer is required")

    # Authorization letter: must exist, must be non-empty, hash is recorded.
    letter_raw = str(eng.get("authorization_letter", "")).strip()
    if not letter_raw:
        raise ValueError(
            "engagement.authorization_letter is required — a run without an "
            "authorization document on file does not start")
    letter = Path(letter_raw)
    if not letter.is_absolute():
        letter = p.parent / letter
    if not letter.exists():
        raise ValueError(f"authorization_letter not found: {letter}")
    letter_bytes = letter.read_bytes()
    if not letter_bytes:
        raise ValueError(f"authorization_letter is empty: {letter}")
    letter_sha = hashlib.sha256(letter_bytes).hexdigest()

    # Assessment window (both bounds optional; inclusive).
    window = eng.get("window") or {}
    if not isinstance(window, dict):
        raise ValueError("engagement.window must be a mapping")
    start = _iso_date(str(window.get("start", "")), "start") \
        if str(window.get("start", "")).strip() else ""
    end = _iso_date(str(window.get("end", "")), "end") \
        if str(window.get("end", "")).strip() else ""
    if start and end and start > end:
        raise ValueError(f"engagement window start {start} is after end {end}")
    today = now or date.today()
    if start and today < date.fromisoformat(start):
        raise ValueError(
            f"engagement window opens {start} — today is {today.isoformat()}; "
            "refusing to run outside the authorized window")
    if end and today > date.fromisoformat(end):
        raise ValueError(
            f"engagement window closed {end} — today is {today.isoformat()}; "
            "refusing to run outside the authorized window")

    scope = eng.get("scope") or {}
    if not isinstance(scope, dict):
        raise ValueError("engagement.scope must be a mapping")
    domains = tuple(str(d).strip() for d in (scope.get("allow_domains") or [])
                    if str(d).strip())
    cidrs = tuple(str(c).strip() for c in (scope.get("allow_cidrs") or [])
                  if str(c).strip())
    if not domains and not cidrs:
        raise ValueError(
            "engagement.scope must define allow_domains or allow_cidrs — "
            "an engagement with no scope authorizes nothing")

    return Engagement(
        id=eid,
        customer=customer,
        operator=str(eng.get("operator", "")).strip(),
        letter_path=str(letter),
        letter_sha256=letter_sha,
        window_start=start,
        window_end=end,
        allow_domains=domains,
        allow_cidrs=cidrs,
        allow_subdomains=bool(scope.get("allow_subdomains", True)),
        allow_private=bool(scope.get("allow_private", False)),
        raw_path=str(p),
    )


def apply_engagement(cfg: AppConfig, eng: Engagement) -> AppConfig:
    """Replace the config scope with the engagement's authorization."""
    scope = replace(
        cfg.scope,
        allow_domains=list(eng.allow_domains),
        allow_cidrs=list(eng.allow_cidrs),
        allow_subdomains=eng.allow_subdomains,
        allow_private=eng.allow_private,
    )
    return replace(cfg, scope=scope)


def engagement_audit_detail(eng: Engagement) -> dict:
    """What the audit log records when an engagement is loaded."""
    return {
        "engagement_id": eng.id,
        "customer": eng.customer,
        "operator": eng.operator,
        "authorization_letter": eng.letter_path,
        "authorization_letter_sha256": eng.letter_sha256,
        "window_start": eng.window_start,
        "window_end": eng.window_end,
        "allow_domains": list(eng.allow_domains),
        "allow_cidrs": list(eng.allow_cidrs),
        "allow_private": eng.allow_private,
    }


def engagement_artifact(cfg: AppConfig, eng: Engagement) -> Path:
    """Write an engagement snapshot next to the audit log so a run's
    authorization claims are reconstructible from artifacts alone."""
    out = Path(cfg.safety.artifacts_dir) / "engagement.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(
        json.dumps(engagement_audit_detail(eng), indent=2, ensure_ascii=False),
        encoding="utf-8")
    return out


def stamp_engagement(cfg: AppConfig, eng: Engagement,
                     audit) -> None:
    """Record + persist the engagement load (audit event + artifact)."""
    audit.record("engagement_loaded", actor=eng.operator or "operator",
                 detail=engagement_audit_detail(eng))
    engagement_artifact(cfg, eng)


def parse_iso_datetime(value: str) -> datetime | None:
    """Best-effort ISO parse used by report tooling; None when absent."""
    value = (value or "").strip()
    if not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None
