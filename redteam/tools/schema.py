"""Response schema diff — excessive data exposure (Phase 2.2).

Deterministic comparison of JSON response shapes:

  1. Anonymous vs authenticated fetch of the same URL: fields the
     UNAUTHENTICATED response carries that are sensitive by name
     (password/token/secret/...) and hold real values = confirmed
     unauthenticated data exposure (CWE-200).
  2. Actual field paths vs the operator-documented `expected_fields`:
     anything beyond the documented schema = suspected excessive data
     exposure — the agent decides severity from the field names.
  3. Fields gated behind authentication (auth-only paths) are reported
     as context, not as a finding: that is auth working.

Mass assignment (sending extra fields to overwrite role/ownership) is
deliberately NOT automated here — it requires state-changing writes and
stays a manual, operator-gated test. This tool only reads.

Safety: GET only, anonymous fetch uses a plain ScopedSession (scope +
DNS pinning apply); the authenticated fetch uses the identity's session.
"""

from __future__ import annotations

import json
import re
from typing import Any

from ..auth import SessionManager
from ..http import ScopedSession
from ..redact import redactor
from .base import Tool, ToolError, ToolResult

# Key/field names that suggest sensitive data (matched on leaf names,
# case-insensitive). Deliberately name-based: it is a heuristic that
# produces 'confirmed' only for values that are actually present.
SENSITIVE_KEY_RE = re.compile(
    r"(passw|passwd|password|secret|api_?key|private_?key|access_?token"
    r"|refresh_?token|bearer|authorization|credential|ssn|social_security"
    r"|credit_?card|card_?number|cvv|session_?id|token)",
    re.I,
)
# ...except CSRF/nonces, which every anonymous page legitimately carries.
EXCLUDE_KEY_RE = re.compile(r"(csrf|xsrf|nonce|authenticity)", re.I)

MAX_PATHS = 120
MAX_LIST = 20
EXCERPT = 600


def json_paths(obj: Any, prefix: str = "", depth: int = 0,
               out: dict[str, Any] | None = None) -> dict[str, Any]:
    """Flatten a JSON document to {dotted.path: leaf_value} (arrays as [*])."""
    if out is None:
        out = {}
    if depth > 8 or len(out) >= MAX_PATHS:
        return out
    if isinstance(obj, dict):
        for k, v in obj.items():
            path = f"{prefix}.{k}" if prefix else str(k)
            if isinstance(v, (dict, list)):
                out[path] = "<object>" if isinstance(v, dict) else "<array>"
                json_paths(v, path, depth + 1, out)
            else:
                out[path] = v
    elif isinstance(obj, list):
        for v in obj[:3]:
            json_paths(v, f"{prefix}[*]", depth + 1, out)
    elif prefix:
        # scalar leaf reached outside a dict (e.g. inside an array)
        out[prefix] = obj
    return out


def _leaf(path: str) -> str:
    leaf = path.split(".")[-1]
    return leaf.replace("[*]", "")


def parse_paths(body: str) -> dict[str, Any] | None:
    """{path: value} for a JSON object body; None when not a JSON object."""
    try:
        parsed = json.loads((body or "")[:500_000])
    except (ValueError, RecursionError):
        return None
    if not isinstance(parsed, (dict, list)):
        return None
    return json_paths(parsed)


def _has_value(value: Any) -> bool:
    if value is None or value is False:
        return False
    if isinstance(value, str):
        return len(value.strip()) >= 4
    return value != 0 and value != ""


def schema_verdict(status_anon: int, anon_body: str,
                   status_auth: int | None, auth_body: str | None,
                   expected_fields: list[str]) -> dict:
    """Pure decision function — unit-tested directly, no network."""
    result: dict[str, Any] = {
        "status_anon": status_anon,
        "status_auth": status_auth,
        "expected_fields": list(expected_fields),
        "sensitive_anon_fields": [],
        "extra_fields": [],
        "auth_only_fields": [],
    }

    anon_paths = parse_paths(anon_body) if status_anon < 400 else None
    auth_paths = (parse_paths(auth_body)
                  if status_auth is not None and status_auth < 400 else None)

    if anon_paths is None and auth_paths is None:
        result["verdict"] = "inconclusive"
        result["reason"] = (
            "no usable JSON object response (anon HTTP "
            f"{status_anon}"
            + (f", auth HTTP {status_auth}" if status_auth is not None else "")
            + ") — schema diff needs a JSON endpoint"
        )
        return result

    expected = {e.strip() for e in expected_fields if e and e.strip()}

    # 1) anonymous sensitive exposure — strongest signal, needs a value
    if anon_paths:
        sensitive, empty = [], []
        for path, value in anon_paths.items():
            if _leaf(path) in expected or path in expected:
                continue
            if EXCLUDE_KEY_RE.search(path):
                continue
            if SENSITIVE_KEY_RE.search(path):
                (sensitive if _has_value(value) else empty).append(path)
        result["sensitive_anon_fields"] = sensitive[:MAX_LIST]
        result["sensitive_anon_empty"] = empty[:MAX_LIST]
        if sensitive:
            result["verdict"] = "confirmed"
            result["reason"] = (
                "unauthenticated response carries sensitive-named field(s) "
                f"with values: {sensitive[:MAX_LIST]} — data exposure "
                "without login"
            )
            return result

    # 2) documented-schema diff (on whichever body we have)
    base_paths = auth_paths if auth_paths is not None else anon_paths
    base_label = "authenticated" if auth_paths is not None else "unauthenticated"
    if expected and base_paths:
        extra = [p for p in base_paths
                 if p not in expected and _leaf(p) not in expected]
        result["extra_fields"] = extra[:MAX_LIST]
        if extra:
            result["verdict"] = "suspected"
            result["reason"] = (
                f"the {base_label} response has {len(extra)} field(s) beyond "
                f"the documented schema: {extra[:MAX_LIST]} — possible "
                "excessive data exposure (agent judges severity from names)"
            )
            return result

    # 3) context: what auth unlocks (not a finding)
    if anon_paths is not None and auth_paths is not None:
        auth_only = sorted(set(auth_paths) - set(anon_paths))
        result["auth_only_fields"] = auth_only[:MAX_LIST]

    if not expected and not result["auth_only_fields"] and anon_paths is None:
        result["verdict"] = "inconclusive"
        result["reason"] = (
            f"anonymous fetch failed (HTTP {status_anon}) and no "
            "expected_fields were provided — nothing to diff"
        )
        return result

    result["verdict"] = "no_issue"
    result["reason"] = (
        "no sensitive fields in the unauthenticated response"
        + (" and no fields beyond the documented schema" if expected else "")
        + ("; fields gated behind auth: "
           f"{result['auth_only_fields']}" if result["auth_only_fields"]
           else "")
    )
    return result


class SchemaDiffTool(Tool):
    name = "schema_diff"
    description = (
        "Deterministic response-schema diff for data-exposure checks: fetches "
        "the URL anonymously (and optionally under a logged-in identity), "
        "parses both JSON bodies, and reports (a) sensitive-named fields "
        "present WITHOUT authentication (verdict 'confirmed' if they hold "
        "values), (b) fields beyond the operator-documented expected_fields "
        "(verdict 'suspected'), (c) fields gated behind auth as context. "
        "GET only; never modifies data. Mass-assignment testing is not "
        "automated — that needs writes. Verdicts: confirmed | suspected | "
        "no_issue | inconclusive."
    )
    binary = None
    parameters = {
        "type": "object",
        "properties": {
            "url": {"type": "string", "description": "JSON endpoint (in scope)"},
            "identity": {"type": "string",
                         "description": "Optional logged-in identity for the "
                                        "authenticated fetch (session_login "
                                        "first); omit for anonymous-only"},
            "expected_fields": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Field names the documentation says this "
                               "endpoint returns — anything else is flagged",
            },
        },
        "required": ["url"],
    }

    def __init__(self, sessions: SessionManager):
        self.sessions = sessions

    def run(self, args: dict[str, Any]) -> ToolResult:
        url = str(args["url"])
        identity = str(args.get("identity", "") or "")
        expected = [str(f) for f in (args.get("expected_fields") or [])]

        # resolve the optional authenticated session BEFORE any request so a
        # bad identity fails fast without touching the network
        sess = self.sessions.get_session(identity) if identity else None

        # anonymous baseline — fresh session, no identity headers
        anon = ScopedSession(self.sessions.guard, timeout=15, max_redirects=5)
        resp_anon = anon.get(url)
        body_anon = resp_anon.text or ""

        status_auth: int | None = None
        body_auth: str | None = None
        if sess is not None:
            resp_auth = sess.get(url)
            status_auth = resp_auth.status_code
            body_auth = resp_auth.text or ""

        v = schema_verdict(resp_anon.status_code, body_anon,
                           status_auth, body_auth, expected)

        evidence = (
            f"schema_diff evidence (request/response pair):\n"
            f"anon: GET {url} -> status {resp_anon.status_code}\n"
            + (f"auth={identity}: GET {url} -> status {status_auth}\n"
               if identity else "")
            + f"sensitive_anon={v['sensitive_anon_fields']} "
              f"extra_fields={v['extra_fields']}\n"
            f"anon body excerpt: {body_anon[:EXCERPT]}"
            + (f"\nauth body excerpt: {(body_auth or '')[:EXCERPT]}"
               if identity else "")
        )
        evidence = redactor.scrub(evidence)

        recommendation = {
            "confirmed": "record_finding with status 'confirmed', severity "
                         "per data class (CWE-200) using this evidence",
            "suspected": "record_finding with status 'suspected' + caveat "
                         "listing the extra fields, or tighten expected_fields",
            "no_issue": "do NOT record a finding — note the checked URL in "
                        "coverage",
            "inconclusive": "do NOT record a finding — needs a JSON endpoint "
                            "and/or expected_fields; report as not testable",
        }[v["verdict"]]

        return ToolResult(
            ok=True,
            summary=f"schema_diff verdict: {v['verdict']} — {v['reason']}",
            data={**v, "url": url, "identity": identity,
                  "evidence": evidence, "recommendation": recommendation},
        )
