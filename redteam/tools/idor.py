"""IDOR/BOLA diff engine (Phase 2.2, catalog sections 3 + 4).

Deterministic: replay the same read-only request under two identities and
diff the responses. The AGENT chooses which URL to test and which
object_marker proves ownership (e.g. the owner's email); the VERDICT is
computed here in code — never by a prompt.

Verdicts:
  confirmed           — object_marker (proving A's ownership) also appears
                        in B's response: B can read A's object.
  suspected           — no marker given, but both identities receive
                        near-identical bodies (overlap >= 0.8 over >= 3
                        values): possibly shared/per-user data; needs the
                        agent to supply a marker to confirm.
  access_control_ok   — B is denied (401/403/404) or does not receive the
                        marked object: the control works on this URL.
                        Recording a "checked, works" note, not a finding.
  inconclusive        — A itself cannot access the URL, the marker is
                        missing from A's response, or bodies differ with no
                        marker to compare. The agent must fix the test
                        inputs; this is never reported as a finding.

Safety: GET/HEAD only (read-only), enforced in code. Both identities must
be distinct and logged in. All traffic flows through each identity's
ScopedSession (scope + DNS pinning apply per hop).
"""

from __future__ import annotations

import json
from typing import Any

from ..auth import SessionManager
from ..redact import redactor
from .base import Tool, ToolError, ToolResult

ALLOWED_METHODS = ("GET", "HEAD")
MIN_SHARED_VALUES = 3
SIMILARITY_THRESHOLD = 0.8
MAX_COMPARE_BYTES = 200_000
EVIDENCE_EXCERPT = 1500


def _scalar_values(obj: Any, out: set[str], depth: int = 0) -> set[str]:
    if depth > 12:
        return out
    if isinstance(obj, dict):
        for v in obj.values():
            _scalar_values(v, out, depth + 1)
    elif isinstance(obj, list):
        for v in obj:
            _scalar_values(v, out, depth + 1)
    elif isinstance(obj, (str, int, float, bool)) and obj is not None:
        s = str(obj).strip()
        if len(s) >= 2:
            out.add(s)
    return out


def _comparable_units(text: str) -> set[str]:
    """Scalar leaf values for JSON, stripped lines for anything else."""
    text = text[:MAX_COMPARE_BYTES]
    try:
        return _scalar_values(json.loads(text), set())
    except (ValueError, RecursionError):
        return {ln.strip() for ln in text.splitlines() if ln.strip()}


def similarity(a_text: str, b_text: str) -> tuple[float, int]:
    """(containment overlap of B in A, shared unit count).

    Containment (|A∩B| / min) rather than Jaccard: if B receives the same
    object (plus maybe wrapper differences), containment is ~1.0 even when
    A's response carries extra fields.
    """
    a, b = _comparable_units(a_text), _comparable_units(b_text)
    if not a or not b:
        return 0.0, 0
    shared = len(a & b)
    return shared / min(len(a), len(b)), shared


def verdict_for(
    status_a: int,
    status_b: int,
    body_a: str,
    body_b: str,
    marker: str,
) -> dict:
    """Pure decision function — unit-tested directly, no network."""
    result: dict[str, Any] = {
        "status_a": status_a,
        "status_b": status_b,
        "marker": marker or "",
        "marker_found_in_a": False,
        "marker_found_in_b": False,
        "overlap": 0.0,
        "shared_values": 0,
    }

    if status_a >= 400:
        result["verdict"] = "inconclusive"
        result["reason"] = (
            f"identity A got HTTP {status_a} — A must be able to read the "
            "object before B's access means anything (wrong URL, expired "
            "object, or A lacks the permission)"
        )
        return result

    in_a = bool(marker) and marker in body_a
    in_b = bool(marker) and marker in body_b
    result["marker_found_in_a"] = in_a
    result["marker_found_in_b"] = in_b

    if marker and not in_a:
        result["verdict"] = "inconclusive"
        result["reason"] = (
            f"object_marker {marker!r} is not in identity A's own response — "
            "the marker does not prove ownership of THIS object; fix the "
            "marker or the URL"
        )
        return result

    overlap, shared = similarity(body_a, body_b)
    result["overlap"] = round(overlap, 3)
    result["shared_values"] = shared

    if marker and in_a and in_b:
        result["verdict"] = "confirmed"
        result["reason"] = (
            f"identity B's response contains A's object_marker "
            f"({marker!r}): B can read A's object"
        )
        return result

    if status_b in (401, 403, 404):
        result["verdict"] = "access_control_ok"
        result["reason"] = (
            f"identity B was denied (HTTP {status_b}) — access control works "
            "on this URL"
        )
        return result

    if marker and in_a and status_b < 400:
        result["verdict"] = "access_control_ok"
        result["reason"] = (
            f"identity B got HTTP {status_b} but WITHOUT the object_marker — "
            "B does not see A's marked object (control works; responses "
            "differ by design)"
        )
        return result

    if status_b >= 400:
        result["verdict"] = "access_control_ok"
        result["reason"] = (
            f"identity B got HTTP {status_b} — no cross-identity read"
        )
        return result

    # both readable, no marker to judge ownership
    if overlap >= SIMILARITY_THRESHOLD and shared >= MIN_SHARED_VALUES:
        result["verdict"] = "suspected"
        result["reason"] = (
            f"both identities received near-identical responses "
            f"(overlap {overlap:.0%} over {shared} values) and no "
            "object_marker was provided — if this URL is per-user data, "
            "B is reading A's object; rerun with object_marker set to "
            "A-specific content to confirm"
        )
        return result

    result["verdict"] = "inconclusive"
    result["reason"] = (
        f"both identities got 2xx but the bodies differ "
        f"(overlap {overlap:.0%}); no object_marker to compare — cannot "
        "judge whether B saw A's object"
    )
    return result


class IdoDiffTool(Tool):
    name = "idor_diff"
    description = (
        "Deterministic IDOR/BOLA test: issues the same read-only request "
        "(GET/HEAD only) under two logged-in identities and diffs the "
        "responses in code. Supply object_marker = an A-specific string "
        "(e.g. the owner's email) present in A's response — if B's response "
        "also contains it, the verdict is 'confirmed'. Without a marker, "
        "near-identical bodies are only 'suspected'. Login both identities "
        "with session_login first. Verdicts: confirmed | suspected | "
        "access_control_ok | inconclusive."
    )
    binary = None
    parameters = {
        "type": "object",
        "properties": {
            "url": {"type": "string",
                    "description": "Object URL to test (in scope), e.g. "
                                   "https://shop.test/rest/user/123"},
            "identity_a": {"type": "string",
                           "description": "The identity that OWNS / can read "
                                          "the object (must be logged in)"},
            "identity_b": {"type": "string",
                           "description": "The other identity that must NOT "
                                          "read it (must be logged in)"},
            "method": {"type": "string", "enum": list(ALLOWED_METHODS),
                       "description": "Read-only method (default GET)"},
            "object_marker": {"type": "string",
                              "description": "A-specific string expected in "
                                             "A's response (ownership proof)"},
        },
        "required": ["url", "identity_a", "identity_b"],
    }

    def __init__(self, sessions: SessionManager):
        self.sessions = sessions

    def run(self, args: dict[str, Any]) -> ToolResult:
        url = str(args["url"])
        name_a = str(args["identity_a"])
        name_b = str(args["identity_b"])
        method = str(args.get("method", "GET") or "GET").upper()
        marker = str(args.get("object_marker", "") or "")

        if name_a == name_b:
            raise ToolError(
                "identity_a and identity_b must be two DIFFERENT identities — "
                "an IDOR test compares who sees what"
            )
        if method not in ALLOWED_METHODS:
            raise ToolError(
                f"idor_diff allows read-only methods {ALLOWED_METHODS}, got "
                f"{method!r} — state-changing replays are never automated here"
            )

        sess_a = self.sessions.get_session(name_a)
        sess_b = self.sessions.get_session(name_b)

        resp_a = sess_a.request(method, url)
        resp_b = sess_b.request(method, url)

        body_a = resp_a.text or ""
        body_b = resp_b.text or ""
        v = verdict_for(resp_a.status_code, resp_b.status_code,
                        body_a, body_b, marker)

        evidence = (
            f"idor_diff evidence (request/response pair):\n"
            f"A={name_a}: {method} {url} -> status {resp_a.status_code}\n"
            f"B={name_b}: {method} {url} -> status {resp_b.status_code}\n"
            f"overlap={v['overlap']} shared_values={v['shared_values']} "
            f"marker_in_a={v['marker_found_in_a']} "
            f"marker_in_b={v['marker_found_in_b']}\n"
            f"A body excerpt: {body_a[:600]}\n"
            f"B body excerpt: {body_b[:600]}"
        )
        evidence = redactor.scrub(evidence)

        recommendation = {
            "confirmed": "record_finding with status 'confirmed', severity "
                         "high (CWE-639 authorization bypass) using this "
                         "evidence",
            "suspected": "record_finding with status 'suspected' and the "
                         "caveat, or rerun with object_marker to confirm",
            "access_control_ok": "do NOT record a finding — the control "
                                 "works; note the checked URL in coverage",
            "inconclusive": "do NOT record a finding — fix the URL/marker "
                            "and rerun, or report as not testable",
        }[v["verdict"]]

        summary = f"idor_diff verdict: {v['verdict']} — {v['reason']}"
        return ToolResult(
            ok=True,
            summary=summary,
            data={**v, "url": url, "identity_a": name_a,
                  "identity_b": name_b, "method": method,
                  "evidence": evidence, "recommendation": recommendation},
        )
