"""Bounded race-condition tester (Phase 2.4, catalog section 11).

Double-spend / TOCTOU classes show up only under concurrency: N simultaneous
requests against a "do this once" operation where at most ONE may succeed.
This tool fires a bounded burst (2..5 workers, hard cap 5) and decides the
verdict in code from the response distribution.

The business rule is NOT guessable — the agent declares it:
  expect_success_max (default 1)  how many of the burst may succeed
  expect_status / success_marker  what counts as a success

Verdicts:
  confirmed     — more successes than the invariant allows (CWE-362):
                  the operation is not serialized.
  suspected     — an unexpected status appeared under concurrency (5xx and
                  outside both success and standard-conflict sets), or
                  same-status responses carried different bodies —
                  state-dependent nondeterminism worth manual review.
  no_issue      — successes within the invariant and every response is a
                  success or a standard conflict (409/422/...), consistent
                  per status: the operation is serialized.
  inconclusive  — the burst never succeeded (bad auth/URL — fix inputs) or
                  every attempt was a transport error.

Safety: methods are POST/PUT/PATCH only (writes — reads go through
http_request); count is capped at 5; the whole burst is ONE tool call, so
the operator approves it as a single `ACTIVE REQUEST` prompt showing
method × count. Each worker uses its OWN ScopedSession (no shared
requests.Session across threads), seeded with the identity's cookies and
headers when given; per-hop scope authorization + DNS pinning + kill switch
apply inside every worker. ScopeViolation / kill-switch propagate out of the
pool and abort the stage, as everywhere else.
"""

from __future__ import annotations

import hashlib
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any

import requests

from ..auth import SessionManager
from ..http import ScopedHttpError, ScopedSession
from ..redact import redactor
from .base import Tool, ToolError, ToolResult

MIN_BURST = 2
MAX_BURST = 5
DEFAULT_BURST = 5
BURST_METHODS = ("POST", "PUT", "PATCH")
BODY_EXCERPT = 250
REQUEST_TIMEOUT = 15.0

# statuses that legitimately answer a conflicting/limited write
REJECT_STATUSES = {400, 401, 403, 409, 412, 422, 429}

_DISABLED_MSG = (
    "business-logic testing is disabled — set `safety.business_logic: true` "
    "in config (the whole burst is still one operator confirmation when "
    "enabled)"
)


def _status_groups(outcomes: list[dict]) -> dict[int, list[str]]:
    groups: dict[int, list[str]] = {}
    for o in outcomes:
        if o.get("status") is not None and not o.get("error"):
            groups.setdefault(int(o["status"]), []).append(str(o.get("sha")))
    return groups


def burst_verdict(outcomes: list[dict], expect_success_max: int = 1,
                  success_statuses: set[int] | None = None) -> dict:
    """Pure decision function over the burst outcomes — unit-tested without
    network. Each outcome: {"index", "ok", "status", "sha", "error"}."""
    success = success_statuses or set(range(200, 300))
    result: dict[str, Any] = {
        "count": len(outcomes),
        "statuses": [o.get("status") for o in outcomes],
        "success_count": sum(1 for o in outcomes if o.get("ok")),
        "expect_success_max": expect_success_max,
        "cwe": "CWE-362",
    }

    if all(o.get("error") for o in outcomes):
        result["verdict"] = "inconclusive"
        result["reason"] = (
            "every request in the burst failed in transport "
            f"({outcomes[0].get('error')}) — nothing can be judged"
        )
        return result

    if result["success_count"] == 0:
        result["verdict"] = "inconclusive"
        result["reason"] = (
            f"none of the {len(outcomes)} concurrent requests succeeded "
            f"(statuses {result['statuses']}) — the request itself is wrong "
            "(auth/URL/payload); fix inputs before judging serialization"
        )
        return result

    if result["success_count"] > expect_success_max:
        result["verdict"] = "confirmed"
        result["reason"] = (
            f"{result['success_count']} of {len(outcomes)} concurrent "
            f"requests succeeded but the invariant allows at most "
            f"{expect_success_max} — the operation is not serialized "
            "(double-spend / TOCTOU)"
        )
        return result

    unexpected = sorted({
        int(o["status"]) for o in outcomes
        if not o.get("error") and o.get("status") is not None
        and int(o["status"]) not in success
        and int(o["status"]) not in REJECT_STATUSES
    })
    if unexpected:
        result["verdict"] = "suspected"
        result["unexpected_statuses"] = unexpected
        result["reason"] = (
            f"HTTP {unexpected} appeared under concurrency (outside both "
            "success and standard conflict statuses) — server instability "
            "or an unhandled interleaving; review manually"
        )
        return result

    divergent = [
        status for status, shas in _status_groups(outcomes).items()
        if len(shas) >= 2 and len(set(shas)) >= 2
    ]
    if divergent:
        result["verdict"] = "suspected"
        result["divergent_statuses"] = sorted(divergent)
        result["reason"] = (
            f"responses with the same status ({sorted(divergent)}) carried "
            "different bodies — state-dependent nondeterminism; review the "
            "excerpts manually"
        )
        return result

    result["verdict"] = "no_issue"
    result["reason"] = (
        f"{result['success_count']} success(es) within the invariant (max "
        f"{expect_success_max}); every other response was a standard "
        "conflict with consistent bodies — the operation serializes"
    )
    return result


class RaceBurstTool(Tool):
    name = "race_burst"
    description = (
        "Bounded concurrent burst for double-spend / TOCTOU checks "
        "(CWE-362): fires 2..5 identical write requests (POST/PUT/PATCH) in "
        "parallel and diffs the outcome distribution in code. Declare the "
        "business rule with expect_success_max (default 1: at most one of "
        "the burst may succeed). Verdicts: confirmed (more successes than "
        "the invariant allows) | suspected (unexpected status or divergent "
        "same-status bodies under concurrency) | no_issue | inconclusive "
        "(burst never succeeded — fix inputs). The whole burst is a single "
        "operator-approved action. Requires safety.business_logic: true."
    )
    binary = None
    parameters = {
        "type": "object",
        "properties": {
            "url": {"type": "string",
                    "description": "In-scope endpoint for the raced write"},
            "method": {"type": "string", "enum": list(BURST_METHODS)},
            "count": {"type": "integer", "minimum": MIN_BURST,
                      "maximum": MAX_BURST,
                      "description": "Parallel workers (2..5, default 5)"},
            "data": {"type": "object",
                     "description": "form fields sent by every worker"},
            "json": {"description": "JSON body sent by every worker"},
            "identity": {"type": "string",
                         "description": "Logged-in identity whose session "
                                        "cookies/headers seed every worker"},
            "expect_status": {"description": "Status(es) counting as success "
                                             "(int or list; default 2xx)"},
            "success_marker": {"type": "string",
                               "description": "Substring that must appear in "
                                              "the body for a success "
                                              "(overrides expect_status)"},
            "expect_success_max": {"type": "integer", "minimum": 0,
                                   "description": "Invariant: at most this "
                                                  "many may succeed "
                                                  "(default 1)"},
        },
        "required": ["url", "method"],
    }

    def __init__(self, sessions: SessionManager, enabled: bool = True):
        self.sessions = sessions
        self.enabled = enabled

    def run(self, args: dict[str, Any]) -> ToolResult:
        if not self.enabled:
            raise ToolError(_DISABLED_MSG)

        url = str(args.get("url") or "")
        method = str(args.get("method") or "POST").upper()
        if method not in BURST_METHODS:
            raise ToolError(
                f"race_burst allows write methods {BURST_METHODS} (reads go "
                f"through http_request), got {method!r}"
            )
        if not url.startswith(("http://", "https://")):
            raise ToolError(f"url must be http(s), got {url[:60]!r}")
        raw_count = args.get("count")
        if raw_count is None:
            count = DEFAULT_BURST
        else:
            try:
                count = int(raw_count)    # note: 0 is rejected below, not defaulted
            except (TypeError, ValueError) as exc:
                raise ToolError("count must be an integer 2..5") from exc
        if not MIN_BURST <= count <= MAX_BURST:
            raise ToolError(
                f"count must be {MIN_BURST}..{MAX_BURST} (bounded burst), "
                f"got {count}"
            )
        try:
            expect_max = int(args.get("expect_success_max")
                             if args.get("expect_success_max") is not None
                             else 1)
        except (TypeError, ValueError) as exc:
            raise ToolError("expect_success_max must be an integer") from exc
        if not 0 <= expect_max <= count:
            raise ToolError(
                f"expect_success_max must be 0..{count} (the burst size), "
                f"got {expect_max}"
            )

        raw_expect = args.get("expect_status")
        success_statuses: set[int] | None = None
        if raw_expect is not None and not args.get("success_marker"):
            values = raw_expect if isinstance(raw_expect, list) else [raw_expect]
            try:
                success_statuses = {int(v) for v in values}
            except (TypeError, ValueError) as exc:
                raise ToolError("expect_status must be integers") from exc
            bad = [s for s in success_statuses if not 100 <= s <= 599]
            if bad:
                raise ToolError(f"expect_status out of range: {bad}")

        # seed each worker with the identity's credentials (own session per
        # thread — requests.Session is not shared across threads)
        seed_headers: dict[str, str] = {}
        seed_cookie = ""
        identity = str(args.get("identity") or "")
        if identity:
            sess = self.sessions.get_session(identity)  # login required
            seed_headers = {
                k: v for k, v in sess.default_headers().items()
                if k.lower() != "cookie"
            }
            cookies = self.sessions.cookies(identity)
            seed_cookie = "; ".join(f"{k}={v}" for k, v in cookies.items())

        data = args.get("data")
        if data is not None and not isinstance(data, dict):
            raise ToolError("data must be an object of form fields")
        body = args.get("json")
        marker = str(args.get("success_marker") or "") or None

        def worker(index: int) -> dict:
            record: dict[str, Any] = {"index": index, "ok": False,
                                      "status": None, "sha": None, "error": None}
            sess = ScopedSession(self.sessions.guard, timeout=REQUEST_TIMEOUT,
                                 max_redirects=5)
            for key, value in seed_headers.items():
                sess.set_default_header(key, value)
            if seed_cookie:
                sess.set_default_header("Cookie", seed_cookie)
            t0 = time.monotonic()
            try:
                resp = sess.request(method, url, data=data, json=body)
            except (requests.RequestException, ScopedHttpError) as exc:
                # transport failure is DATA for a burst (-> inconclusive),
                # not a stage abort; ScopeViolation/KillSwitch still escape
                record["error"] = str(exc)
                record["elapsed_ms"] = int((time.monotonic() - t0) * 1000)
                return record
            text = resp.text or ""
            record["status"] = resp.status_code
            record["elapsed_ms"] = int((time.monotonic() - t0) * 1000)
            record["sha"] = hashlib.sha1(
                text[:100_000].encode("utf-8", "replace")).hexdigest()[:12]
            record["body"] = text
            if marker:
                record["ok"] = marker in text
            elif success_statuses:
                record["ok"] = resp.status_code in success_statuses
            else:
                record["ok"] = 200 <= resp.status_code < 300
            return record

        # ScopeViolation / KillSwitchEngaged raised inside a worker surface
        # through future.result() and propagate (stage aborts), as everywhere
        with ThreadPoolExecutor(max_workers=count) as pool:
            futures = [pool.submit(worker, i) for i in range(count)]
            outcomes = [f.result() for f in futures]

        allowed = success_statuses or set(range(200, 300))
        v = burst_verdict(outcomes, expect_success_max=expect_max,
                          success_statuses=allowed)

        lines = [
            f"race_burst evidence: {count} concurrent {method} {url} "
            f"(invariant: at most {expect_max} success(es))"
        ]
        excerpts: list[str] = []
        seen_sha: set[str] = set()
        for o in outcomes:
            if o.get("error"):
                lines.append(f"req {o['index']}: transport error "
                             f"{o['error']}")
                continue
            lines.append(
                f"req {o['index']}: status {o['status']} len {len(o.get('body') or '')} "
                f"sha1 {o['sha']} elapsed {o['elapsed_ms']}ms"
            )
            sha = str(o["sha"])
            if sha not in seen_sha and len(excerpts) < 2:
                seen_sha.add(sha)
                excerpts.append(
                    f"  body[{sha}]: {(o.get('body') or '')[:BODY_EXCERPT]}")
        evidence = redactor.scrub("\n".join(lines + excerpts))

        recommendation = {
            "confirmed": "record_finding with status 'confirmed' "
                         "(CWE-362, severity per business impact) using this "
                         "burst evidence",
            "suspected": "record_finding with status 'suspected' and the "
                         "concurrency caveat, or re-run with a smaller "
                         "count / review the divergent bodies manually",
            "no_issue": "do NOT record a finding — note the endpoint as "
                        "serialized under concurrency in coverage",
            "inconclusive": "do NOT record a finding — fix auth/URL/payload "
                            "and rerun",
        }[v["verdict"]]

        return ToolResult(
            ok=True,
            summary=f"race_burst verdict: {v['verdict']} — {v['reason']}",
            data={
                **v,
                "url": url,
                "method": method,
                "identity": identity or "(anonymous)",
                "evidence": evidence,
                "recommendation": recommendation,
            },
        )
