"""BFLA — Broken Function Level Authorization checks (Phase 2.2).

Same shape as IDOR but at the privilege boundary: call a privileged
endpoint under a high-privilege identity (A) and a low-privilege one (B).
The verdict is computed in code:

  confirmed           — B receives a near-identical copy of A's privileged
                        response (or A's marker appears in B's response).
  suspected           — B gets ANY undenied 2xx from the privileged
                        endpoint with a different body: privileged
                        functionality is reachable; inspect the excerpt.
  access_control_ok   — B is denied (401/403/404) or the 2xx body is a
                        soft denial ("unauthorized"/"forbidden"/...), or
                        B's 2xx lacks A's marker: the boundary holds.
  inconclusive        — A itself cannot access the endpoint, or the marker
                        is missing from A's response.

Safety: GET/HEAD only, enforced in code — probing privilege boundaries
must never modify data automatically. State-changing BFLA (DELETE/POST
actions) is deliberately left for manual, operator-gated testing.
"""

from __future__ import annotations

from typing import Any

from ..auth import SessionManager
from ..redact import redactor
from .base import Tool, ToolError, ToolResult
from .idor import MIN_SHARED_VALUES, SIMILARITY_THRESHOLD, similarity

ALLOWED_METHODS = ("GET", "HEAD")

# 2xx bodies that are really denials wrapped in an OK status
SOFT_DENIAL_MARKERS = (
    "unauthorized", "unauthenticated", "forbidden", "access denied",
    "permission denied", "not allowed", "insufficient privilege",
    "admin only", "requires admin", "not permitted",
)


def bfla_verdict(status_a: int, status_b: int, body_a: str, body_b: str,
                 marker: str = "") -> dict:
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
            f"privileged identity A got HTTP {status_a} — A must be able to "
            "use the endpoint before B's access means anything (wrong URL "
            "or A is not actually privileged for it)"
        )
        return result

    in_a = bool(marker) and marker in body_a
    in_b = bool(marker) and marker in body_b
    result["marker_found_in_a"] = in_a
    result["marker_found_in_b"] = in_b

    if marker and not in_a:
        result["verdict"] = "inconclusive"
        result["reason"] = (
            f"marker {marker!r} is not in the privileged identity's own "
            "response — it does not prove privilege for THIS endpoint; "
            "fix the marker or the URL"
        )
        return result

    overlap, shared = similarity(body_a, body_b)
    result["overlap"] = round(overlap, 3)
    result["shared_values"] = shared

    if marker and in_a and in_b:
        result["verdict"] = "confirmed"
        result["reason"] = (
            f"low-privilege identity B's response contains A's marker "
            f"({marker!r}): B reached privileged content"
        )
        return result

    if status_b in (401, 403, 404):
        result["verdict"] = "access_control_ok"
        result["reason"] = (
            f"low-privilege identity B was denied (HTTP {status_b}) — "
            "function-level authorization works on this endpoint"
        )
        return result

    if status_b >= 400:
        result["verdict"] = "access_control_ok"
        result["reason"] = (
            f"identity B got HTTP {status_b} — B cannot use this endpoint"
        )
        return result

    low = (body_b or "").lower()
    soft = next((m for m in SOFT_DENIAL_MARKERS if m in low), "")
    if soft:
        result["verdict"] = "access_control_ok"
        result["reason"] = (
            f"identity B got HTTP {status_b} but the body is a soft denial "
            f"(contains {soft!r}) — boundary holds"
        )
        return result

    if marker and in_a and status_b < 400:
        result["verdict"] = "access_control_ok"
        result["reason"] = (
            f"identity B got HTTP {status_b} WITHOUT the privileged marker "
            "— B did not receive A's privileged content"
        )
        return result

    if overlap >= SIMILARITY_THRESHOLD and shared >= MIN_SHARED_VALUES:
        result["verdict"] = "confirmed"
        result["reason"] = (
            f"low-privilege identity B received a near-identical copy of "
            f"the privileged response (overlap {overlap:.0%} over {shared} "
            "values) — broken function-level authorization"
        )
        return result

    result["verdict"] = "suspected"
    result["reason"] = (
        f"low-privilege identity B got HTTP {status_b} from a privileged "
        f"endpoint with a different body (overlap {overlap:.0%}) — "
        "privileged functionality is reachable by B; inspect the excerpt "
        "to decide whether privileged data or actions leaked"
    )
    return result


class BflaCheckTool(Tool):
    name = "bfla_check"
    description = (
        "Deterministic Broken Function-Level Authorization test: calls a "
        "privileged endpoint (GET/HEAD only) under a high-privilege identity "
        "and a low-privilege one, then diffs the outcomes in code. "
        "identity_privileged must get a non-error response first, otherwise "
        "the result is 'inconclusive'. Optional marker = a string only the "
        "privileged response should contain (e.g. an admin-only value). "
        "Verdicts: confirmed | suspected | access_control_ok | inconclusive. "
        "Login both identities with session_login first."
    )
    binary = None
    parameters = {
        "type": "object",
        "properties": {
            "url": {"type": "string",
                    "description": "Privileged endpoint URL (in scope)"},
            "identity_privileged": {"type": "string",
                                    "description": "Identity that SHOULD be "
                                                   "allowed (logged in)"},
            "identity_lowpriv": {"type": "string",
                                 "description": "Identity that should NOT be "
                                                "allowed (logged in)"},
            "method": {"type": "string", "enum": list(ALLOWED_METHODS),
                       "description": "Read-only method (default GET)"},
            "marker": {"type": "string",
                       "description": "Privileged-only string expected in "
                                      "the privileged identity's response"},
        },
        "required": ["url", "identity_privileged", "identity_lowpriv"],
    }

    def __init__(self, sessions: SessionManager):
        self.sessions = sessions

    def run(self, args: dict[str, Any]) -> ToolResult:
        url = str(args["url"])
        name_a = str(args["identity_privileged"])
        name_b = str(args["identity_lowpriv"])
        method = str(args.get("method", "GET") or "GET").upper()
        marker = str(args.get("marker", "") or "")

        if name_a == name_b:
            raise ToolError(
                "identity_privileged and identity_lowpriv must be two "
                "DIFFERENT identities — BFLA compares privilege levels"
            )
        if method not in ALLOWED_METHODS:
            raise ToolError(
                f"bfla_check allows read-only methods {ALLOWED_METHODS}, got "
                f"{method!r} — state-changing privilege probes are never "
                "automated"
            )

        sess_a = self.sessions.get_session(name_a)
        sess_b = self.sessions.get_session(name_b)

        resp_a = sess_a.request(method, url)
        resp_b = sess_b.request(method, url)
        body_a, body_b = resp_a.text or "", resp_b.text or ""

        v = bfla_verdict(resp_a.status_code, resp_b.status_code,
                         body_a, body_b, marker)

        evidence = (
            f"bfla_check evidence (request/response pair):\n"
            f"privileged={name_a}: {method} {url} -> status "
            f"{resp_a.status_code}\n"
            f"lowpriv={name_b}: {method} {url} -> status "
            f"{resp_b.status_code}\n"
            f"overlap={v['overlap']} shared_values={v['shared_values']} "
            f"marker_in_privileged={v['marker_found_in_a']} "
            f"marker_in_lowpriv={v['marker_found_in_b']}\n"
            f"privileged body excerpt: {body_a[:600]}\n"
            f"lowpriv body excerpt: {body_b[:600]}"
        )
        evidence = redactor.scrub(evidence)

        recommendation = {
            "confirmed": "record_finding with status 'confirmed', severity "
                         "high (CWE-285 improper authorization) using this "
                         "evidence",
            "suspected": "record_finding with status 'suspected' + caveat, "
                         "or inspect the excerpt and rerun with a marker "
                         "to confirm",
            "access_control_ok": "do NOT record a finding — the privilege "
                                 "boundary holds; note the checked URL",
            "inconclusive": "do NOT record a finding — fix the URL/marker "
                            "and rerun, or report as not testable",
        }[v["verdict"]]

        return ToolResult(
            ok=True,
            summary=f"bfla_check verdict: {v['verdict']} — {v['reason']}",
            data={**v, "url": url, "identity_privileged": name_a,
                  "identity_lowpriv": name_b, "method": method,
                  "evidence": evidence, "recommendation": recommendation},
        )
