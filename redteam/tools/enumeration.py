"""Account-enumeration diff engine (Phase 2.3, catalog section 2).

A login/registration/recovery endpoint that answers differently for an
existing account than for a non-existent one is an enumeration oracle: it
turns credential stuffing and user-profile discovery into a one-request
lookup. This engine sends EXACTLY TWO requests with the same WRONG password
that is generated locally and never comes from config:

  * existing username — operator-supplied identity's username (env var)
  * a generated non-existent username

and compares the responses in code. The agent supplies only the URL, the
identity whose account name is known to exist, and the field name.

Verdicts:
  confirmed     — the fake-account response carries an existence message
                  ("no such user" / "account not found" ...) that the real
                  account's response lacks: the endpoint is an oracle.
  suspected     — status code and/or normalized body differ between the two
                  probes, with no explicit existence wording.
  no_issue      — both probes answer identically (after normalizing away the
                  echoed username): no observable discrepancy.
  inconclusive  — server error / transport failure / unset env var.

Honesty: this is a *response discrepancy* test (CWE-204), not proof of an
account list. Timing side-channels are deliberately NOT measured (too noisy
to report as evidence). Two wrong-password attempts are sent — small enough
to avoid lockout thresholds, but the tool is still operator-gated because it
touches a credential endpoint and consumes failed-attempt counters.
"""

from __future__ import annotations

import os
import re
import secrets
from typing import Any

from ..auth import SessionManager
from ..http import ScopedSession
from ..redact import redactor
from .base import Tool, ToolError, ToolResult

ALLOWED_METHODS = ("POST", "GET")
EVIDENCE_EXCERPT = 400

# explicit "this account does not exist" wording, checked on the FAKE probe
NEGATIVE_MARKERS = (
    "not exist", "no such user", "no account", "does not exist",
    "unknown user", "unrecognized", "no user found", "user not found",
    "account not found", "not registered", "invalid user", "no matching",
)
# wording that indicates the account EXISTS (credentials were the problem)
POSITIVE_MARKERS = (
    "invalid password", "incorrect password", "wrong password",
    "password is invalid", "authentication failed", "invalid credentials",
)
_WS = re.compile(r"\s+")


def generate_fake_username(existing: str, field: str) -> str:
    """A syntactically valid, definitely-nonexistent account name."""
    token = f"rt-enum-{secrets.token_hex(6)}"
    if "mail" in field.lower() or "@" in existing:
        return f"{token}@invalid.example"
    return token


def normalize_body(text: str, usernames: list[str]) -> str:
    """Lower-case, collapse whitespace, and mask the probe usernames so the
    server merely echoing the submitted name is not mistaken for a leak."""
    out = (text or "").lower()
    for name in usernames:
        if name:
            out = out.replace(name.lower(), "<user>")
    return _WS.sub(" ", out).strip()


def _markers(text: str, markers: tuple[str, ...]) -> list[str]:
    low = (text or "").lower()
    return [m for m in markers if m in low]


def enum_verdict(status_real: int, status_fake: int, body_real: str,
                 body_fake: str, usernames: list[str]) -> dict:
    """Pure decision function — unit-tested directly, no network."""
    result: dict[str, Any] = {
        "status_real": status_real,
        "status_fake": status_fake,
        "status_differs": status_real != status_fake,
        "bodies_identical": False,
        "negative_markers_in_fake": [],
        "positive_markers_in_real": [],
        "cwe": "CWE-204",
    }

    if status_real >= 500 or status_fake >= 500:
        result["verdict"] = "inconclusive"
        result["reason"] = (
            f"server error during probing (HTTP {status_real} / "
            f"{status_fake}) — cannot judge an enumeration oracle"
        )
        return result

    norm_real = normalize_body(body_real, usernames)
    norm_fake = normalize_body(body_fake, usernames)
    result["bodies_identical"] = norm_real == norm_fake

    neg = _markers(body_fake, NEGATIVE_MARKERS)
    neg_in_real = _markers(body_real, NEGATIVE_MARKERS)
    pos_real = _markers(body_real, POSITIVE_MARKERS)
    result["negative_markers_in_fake"] = neg
    result["positive_markers_in_real"] = pos_real

    if norm_real == norm_fake and not result["status_differs"]:
        result["verdict"] = "no_issue"
        result["reason"] = (
            "both probes returned the same status and the same body (after "
            "masking the submitted username) — no observable account "
            "enumeration on this endpoint"
        )
        return result

    # explicit oracle: the fake account is told it does not exist, while the
    # real account is told the credentials were wrong
    if neg and not neg_in_real:
        result["verdict"] = "confirmed"
        result["reason"] = (
            f"the non-existent account's response carries an existence "
            f"message ({neg[0]!r}) that the existing account's response does "
            "not — the endpoint reveals whether an account exists"
        )
        return result

    if pos_real and not _markers(body_fake, POSITIVE_MARKERS):
        result["verdict"] = "confirmed"
        result["reason"] = (
            f"the existing account is told its credentials were wrong "
            f"({pos_real[0]!r}) while the non-existent account is not — the "
            "endpoint distinguishes real accounts from fake ones"
        )
        return result

    if result["status_differs"]:
        result["verdict"] = "suspected"
        result["reason"] = (
            f"the two probes differ in status (HTTP {status_real} vs "
            f"{status_fake}) — a discrepancy with no explicit existence "
            "wording; consider it suspected and re-check manually"
        )
        return result

    result["verdict"] = "suspected"
    result["reason"] = (
        "the two probes differ in body content (after masking the submitted "
        "username) with no explicit existence wording — suspected response "
        "discrepancy (CWE-204)"
    )
    return result


class AccountEnumTool(Tool):
    name = "account_enum"
    description = (
        "Account-enumeration probe: sends exactly TWO requests to an "
        "authentication endpoint (login/registration/password-reset) with a "
        "locally generated WRONG password — one for an operator-configured "
        "existing account, one for a generated non-existent account — and "
        "diffs the responses in code. Verdicts: confirmed (explicit "
        "existence wording only in the fake-account response) | suspected "
        "(status/body discrepancy, no wording) | no_issue (identical) | "
        "inconclusive. The known account name comes from the identity's "
        "username_env; the password is never read from config. "
        "Operator-gated: it consumes failed-login attempts."
    )
    binary = None
    parameters = {
        "type": "object",
        "properties": {
            "url": {"type": "string",
                    "description": "Authentication endpoint (in scope), "
                                   "e.g. https://shop.test/rest/user/login"},
            "identity": {"type": "string",
                         "description": "Configured identity whose username "
                                        "is known to exist on the target"},
            "field": {"type": "string",
                      "description": "Username/email form field name "
                                     "(default 'email')"},
            "password_field": {"type": "string",
                               "description": "Password field name "
                                              "(default 'password')"},
            "method": {"type": "string", "enum": list(ALLOWED_METHODS),
                       "description": "HTTP method (default POST)"},
        },
        "required": ["url", "identity"],
    }

    def __init__(self, sessions: SessionManager):
        self.sessions = sessions

    def run(self, args: dict[str, Any]) -> ToolResult:
        url = str(args["url"])
        name = str(args["identity"])
        field = str(args.get("field", "email") or "email")
        pw_field = str(args.get("password_field", "password") or "password")
        method = str(args.get("method", "POST") or "POST").upper()

        if method not in ALLOWED_METHODS:
            raise ToolError(
                f"account_enum allows {ALLOWED_METHODS} (form/query probes), "
                f"got {method!r}"
            )

        ident = self.sessions.identity(name)
        if not ident.username_env:
            raise ToolError(
                f"identity {name!r} has no username_env configured — "
                "account_enum needs a known-existing account name"
            )
        existing = os.environ.get(ident.username_env, "")
        if not existing:
            raise ToolError(
                f"identity {name!r}: environment variable "
                f"{ident.username_env} is not set"
            )
        redactor.register(existing)

        fake = generate_fake_username(existing, field)
        wrong = secrets.token_urlsafe(12)  # never from config, never correct

        def probe(username: str):
            payload = {field: username, pw_field: wrong,
                       **ident.extra_fields}
            sess = ScopedSession(self.sessions.guard, timeout=15,
                                 max_redirects=5)
            if method == "GET":
                query = "&".join(f"{k}={v}" for k, v in payload.items())
                sep = "&" if "?" in url else "?"
                return sess.request("GET", f"{url}{sep}{query}")
            return sess.request("POST", url, data=payload)

        resp_real = probe(existing)
        resp_fake = probe(fake)

        body_real = resp_real.text or ""
        body_fake = resp_fake.text or ""
        v = enum_verdict(resp_real.status_code, resp_fake.status_code,
                         body_real, body_fake, [existing, fake])

        evidence = (
            f"account_enum evidence (request/response pair, wrong password "
            f"used for both — value never from config):\n"
            f"probed accounts: existing="
            f"{redactor.scrub(existing)} fake={fake}\n"
            f"existing account: {method} {url} -> status "
            f"{resp_real.status_code}\n"
            f"  body: {body_real[:EVIDENCE_EXCERPT]}\n"
            f"fake account: {method} {url} -> status {resp_fake.status_code}\n"
            f"  body: {body_fake[:EVIDENCE_EXCERPT]}\n"
            f"status_differs={v['status_differs']} "
            f"bodies_identical={v['bodies_identical']} "
            f"markers_in_fake={v['negative_markers_in_fake']}"
        )
        evidence = redactor.scrub(evidence)

        recommendation = {
            "confirmed": "record_finding with status 'confirmed' (CWE-204, "
                         "severity low/medium) — generic error messages fix "
                         "this",
            "suspected": "record_finding with status 'suspected' and the "
                         "discrepancy caveat, or re-check manually",
            "no_issue": "do NOT record a finding — note the endpoint as "
                        "checked in coverage",
            "inconclusive": "do NOT record a finding — fix the URL/identity "
                            "and rerun, or report as not testable",
        }[v["verdict"]]

        return ToolResult(
            ok=True,
            summary=f"account_enum verdict: {v['verdict']} — {v['reason']}",
            data={**v, "url": url, "identity": name, "method": method,
                  "field": field, "fake_username": fake,
                  "evidence": evidence, "recommendation": recommendation},
        )
