"""Session-lifecycle checks (Phase 2.3, catalog section 2).

Three deterministic probes behind one tool; the agent picks the check, the
verdict is computed in code.

  cookie_flags — inspect the session cookie(s) the target issues.
                 Missing HttpOnly            -> confirmed (CWE-1004)
                 Missing Secure on an https URL -> confirmed (CWE-614)
                 Missing SameSite            -> suspected (CWE-1275)
                 Lifetime > 24h              -> suspected (CWE-613)

  logout       — replay-after-logout. GET a protected URL with the live
                 session (precondition), POST the identity's logout_url,
                 then replay the SAME captured cookie from a fresh session.
                 Still readable -> confirmed (CWE-613): the server never
                 invalidated the session.

  fixation     — capture an anonymous pre-auth cookie, log the identity in
                 while sending that cookie, and compare the post-login
                 session cookie. Unchanged identifier -> confirmed
                 (CWE-384): the session is not rotated on authentication.

Verdicts: confirmed | suspected | no_issue | inconclusive.
Safety: GET for reads; the only writes are the identity's own logout. All
traffic flows through ScopedSession (per-hop scope + DNS pinning).
"""

from __future__ import annotations

import re
import time
from typing import Any

from ..auth import SessionManager
from ..http import ScopedSession
from ..redact import redactor
from .base import Tool, ToolError, ToolResult

CHECKS = ("cookie_flags", "logout", "fixation")
SESSION_COOKIE_RE = re.compile(r"session|sess|sid|auth|token|jwt|remember", re.I)
MAX_LIFETIME_HOURS = 24
EVIDENCE_EXCERPT = 400


def _is_session_cookie(name: str) -> bool:
    return bool(SESSION_COOKIE_RE.search(name or ""))


def cookie_flag_verdict(cookies: list[dict], https: bool,
                        now: float | None = None) -> dict:
    """Pure: flag hygiene problems on the session-ish cookies."""
    now = time.time() if now is None else now
    result: dict[str, Any] = {"cookies": [c.get("name") for c in cookies],
                              "confirmed": [], "suspected": [], "cwe": ""}
    if not cookies:
        result["verdict"] = "inconclusive"
        result["reason"] = (
            "no cookies in the session jar — run session_login for this "
            "identity first (static cookie identities carry no jar)"
        )
        return result

    sessionish = [c for c in cookies if _is_session_cookie(str(c.get("name", "")))]
    if not sessionish:
        result["verdict"] = "inconclusive"
        result["reason"] = (
            f"no session-like cookie among {result['cookies']} — set-flag "
            "check needs the cookie that carries the session"
        )
        return result

    for c in sessionish:
        name = str(c.get("name"))
        if not c.get("httponly"):
            result["confirmed"].append(
                f"{name}: HttpOnly missing — session readable by JS (CWE-1004)")
        if https and not c.get("secure"):
            result["confirmed"].append(
                f"{name}: Secure missing over HTTPS (CWE-614)")
        if not c.get("samesite"):
            result["suspected"].append(
                f"{name}: SameSite not set (CWE-1275)")
        expires = c.get("expires")
        if isinstance(expires, (int, float)):
            hours = (float(expires) - now) / 3600
            if hours > MAX_LIFETIME_HOURS:
                result["suspected"].append(
                    f"{name}: lifetime {hours:.0f}h exceeds "
                    f"{MAX_LIFETIME_HOURS}h (CWE-613)")

    if result["confirmed"]:
        result["verdict"] = "confirmed"
        result["cwe"] = "CWE-1004"
        result["reason"] = "; ".join(result["confirmed"])
        return result
    if result["suspected"]:
        result["verdict"] = "suspected"
        result["cwe"] = "CWE-1275"
        result["reason"] = "; ".join(result["suspected"])
        return result
    result["verdict"] = "no_issue"
    result["reason"] = (
        "session cookie(s) carry HttpOnly, Secure and SameSite with a "
        f"lifetime <= {MAX_LIFETIME_HOURS}h"
    )
    return result


def logout_verdict(status_pre: int, status_logout: int,
                   status_post: int) -> dict:
    """Pure: session-still-valid-after-logout decision."""
    result: dict[str, Any] = {
        "status_pre": status_pre,
        "status_logout": status_logout,
        "status_post": status_post,
        "cwe": "CWE-613",
    }
    if status_pre >= 400:
        result["verdict"] = "inconclusive"
        result["reason"] = (
            f"the protected URL returned HTTP {status_pre} WITH the live "
            "session — pick a URL the identity can actually read"
        )
        return result
    if status_logout >= 500:
        result["verdict"] = "inconclusive"
        result["reason"] = (
            f"logout endpoint returned HTTP {status_logout} — server error, "
            "cannot judge invalidation"
        )
        return result
    if 400 <= status_logout < 500:
        result["verdict"] = "inconclusive"
        result["reason"] = (
            f"logout endpoint returned HTTP {status_logout} (rejected — "
            "often a missing CSRF token); the logout could not be performed "
            "automatically"
        )
        return result
    if status_post < 400:
        result["verdict"] = "confirmed"
        result["reason"] = (
            f"the captured session cookie still reads the protected URL "
            f"(HTTP {status_post}) AFTER logout — the server never "
            "invalidated the session"
        )
        return result
    result["verdict"] = "no_issue"
    result["reason"] = (
        f"the captured cookie was rejected after logout (HTTP {status_post}) "
        "— server-side invalidation works"
    )
    return result


def fixation_verdict(pre_cookies: dict[str, str],
                     post_cookies: dict[str, str]) -> dict:
    """Pure: did the session identifier survive authentication unchanged?

    Only session-like cookie names are considered, so unrelated cookies
    (locale, consent) cannot fake a positive.
    """
    pre = {k: v for k, v in pre_cookies.items() if _is_session_cookie(k)}
    post = {k: v for k, v in post_cookies.items() if _is_session_cookie(k)}
    result: dict[str, Any] = {
        "pre_session_cookies": sorted(pre),
        "post_session_cookies": sorted(post),
        "unchanged": [],
        "cwe": "CWE-384",
    }
    if not pre:
        result["verdict"] = "inconclusive"
        result["reason"] = (
            "the server issued no pre-authentication session cookie — a "
            "fixation test is not applicable to this endpoint"
        )
        return result

    unchanged = [k for k in pre if k in post and post[k] == pre[k]]
    result["unchanged"] = unchanged
    if unchanged:
        result["verdict"] = "confirmed"
        result["reason"] = (
            f"the session identifier {unchanged} is byte-identical before "
            "and after authentication — the server does not rotate the "
            "session on login (fixation)"
        )
        return result
    result["verdict"] = "no_issue"
    result["reason"] = (
        "the session identifier was replaced (or discarded) during login — "
        "no fixation"
    )
    return result


def _cookie_header(cookies: dict[str, str]) -> str:
    return "; ".join(f"{k}={v}" for k, v in cookies.items())


class SessionCheckTool(Tool):
    name = "session_check"
    description = (
        "Session-lifecycle probes on an operator-configured identity. "
        "check=cookie_flags inspects the target's session cookie (HttpOnly/"
        "Secure/SameSite/lifetime). check=logout replays a captured cookie "
        "after POSTing the identity's logout_url — still valid means the "
        "server did not invalidate the session. check=fixation logs in while "
        "sending a captured pre-auth cookie and checks whether the session "
        "identifier changed. Verdicts: confirmed | suspected | no_issue | "
        "inconclusive. Operator-gated: logout is a state change on our own "
        "session."
    )
    binary = None
    parameters = {
        "type": "object",
        "properties": {
            "check": {"type": "string", "enum": list(CHECKS),
                      "description": "Which lifecycle probe to run"},
            "identity": {"type": "string",
                         "description": "Configured identity to probe"},
            "url": {"type": "string",
                    "description": "For logout: a protected URL the identity "
                                   "can read. For fixation: a URL that issues "
                                   "a pre-auth session cookie (e.g. the login "
                                   "page). Defaults to the identity's "
                                   "verify_url."},
        },
        "required": ["check", "identity"],
    }

    def __init__(self, sessions: SessionManager):
        self.sessions = sessions

    def run(self, args: dict[str, Any]) -> ToolResult:
        check = str(args.get("check", "") or "")
        name = str(args.get("identity", "") or "")
        if check not in CHECKS:
            raise ToolError(f"check must be one of {CHECKS}, got {check!r}")
        if not name:
            raise ToolError("identity is required")

        if check == "cookie_flags":
            return self._cookie_flags(name, str(args.get("url", "") or ""))
        if check == "logout":
            return self._logout(name, str(args.get("url", "") or ""))
        return self._fixation(name, str(args.get("url", "") or ""))

    # ---- probes ------------------------------------------------------------

    def _cookie_flags(self, name: str, url: str) -> ToolResult:
        ident = self.sessions.identity(name)
        target = url or ident.verify_url
        if not target:
            raise ToolError(
                "cookie_flags needs a url (or a verify_url on the identity) "
                "to observe the session cookie"
            )
        sess = self.sessions.get_session(name)
        resp = sess.get(target)
        cookies = sess.cookie_details()
        v = cookie_flag_verdict(cookies, https=target.startswith("https://"))

        evidence = (
            f"session_check cookie_flags evidence:\n"
            f"GET {target} -> status {resp.status_code}\n"
            f"cookie attributes: "
            + "; ".join(
                f"{c.get('name')}[httponly={c.get('httponly')} "
                f"secure={c.get('secure')} samesite={c.get('samesite') or '-'} "
                f"expires={c.get('expires')}]" for c in cookies)
        )
        return self._result("cookie_flags", name, v, evidence,
                            extra={"url": target, "cookies": v["cookies"]})

    def _logout(self, name: str, url: str) -> ToolResult:
        ident = self.sessions.identity(name)
        target = url or ident.verify_url
        if not target:
            raise ToolError(
                "logout needs a url (or a verify_url on the identity): a "
                "protected URL the identity can read while logged in"
            )
        if not ident.logout_url:
            v = {"verdict": "inconclusive", "cwe": "CWE-613",
                 "reason": "no logout_url configured on this identity — add "
                           "one to test logout invalidation",
                 "status_pre": None, "status_logout": None,
                 "status_post": None}
            return self._result("logout", name, v, "session_check logout: "
                                "not run (logout_url unset)")

        sess = self.sessions.get_session(name)
        resp_pre = sess.get(target)
        captured = dict(sess.cookies())
        for part in sess.cookie_header().split(";"):
            key, _, value = part.partition("=")
            if key.strip() and key.strip() not in captured:
                captured[key.strip()] = value.strip()

        resp_logout = sess.request("POST", ident.logout_url)

        fresh = ScopedSession(self.sessions.guard, timeout=15, max_redirects=5)
        # the captured cookie is live credential material — register it so
        # the evidence below can never carry it verbatim
        for value in captured.values():
            if value:
                redactor.register(value)
        if captured:
            fresh.set_default_header("Cookie", _cookie_header(captured))
        resp_post = fresh.get(target)

        v = logout_verdict(resp_pre.status_code, resp_logout.status_code,
                           resp_post.status_code)
        evidence = (
            f"session_check logout evidence (replay-after-logout):\n"
            f"pre: GET {target} with live session -> status "
            f"{resp_pre.status_code}\n"
            f"POST {ident.logout_url} -> status {resp_logout.status_code}\n"
            f"replayed cookies: {redactor.scrub(_cookie_header(captured))}\n"
            f"post: GET {target} with captured cookie (fresh session) -> "
            f"status {resp_post.status_code}\n"
            f"post body excerpt: {(resp_post.text or '')[:EVIDENCE_EXCERPT]}"
        )
        return self._result(
            "logout", name, v, evidence,
            extra={"url": target, "logout_url": ident.logout_url,
                   "note": "the probed session may now be invalidated — "
                           "session_login again if you need this identity"})

    def _fixation(self, name: str, url: str) -> ToolResult:
        ident = self.sessions.identity(name)
        target = url or ident.verify_url or ident.login_url
        if not target:
            raise ToolError("fixation needs a url that issues a pre-auth "
                            "session cookie")

        anon = ScopedSession(self.sessions.guard, timeout=15, max_redirects=5)
        resp_anon = anon.get(target)
        pre = dict(anon.cookies())
        if not pre:
            v = fixation_verdict({}, {})
            return self._result(
                "fixation", name, v,
                f"session_check fixation: GET {target} -> status "
                f"{resp_anon.status_code}; no pre-auth cookie issued",
                extra={"url": target})

        pre_session = {k: v for k, v in pre.items() if _is_session_cookie(k)}
        preflight = _cookie_header(pre_session or pre)
        meta = self.sessions.login(name, preflight_cookie=preflight)
        post = self.sessions.cookies(name)

        v = fixation_verdict(pre, post)
        evidence = (
            f"session_check fixation evidence:\n"
            f"anonymous GET {target} -> status {resp_anon.status_code}, "
            f"pre-auth cookies: {sorted(pre)}\n"
            f"login with pre-auth cookie sent -> login_status "
            f"{meta.login_status}, verified={meta.verified}\n"
            f"post-login cookies: {sorted(post)}\n"
            f"unchanged identifiers: {v['unchanged']}"
        )
        return self._result("fixation", name, v, evidence,
                            extra={"url": target})

    # ---- shared ------------------------------------------------------------

    def _result(self, check: str, name: str, v: dict, evidence: str,
                extra: dict | None = None) -> ToolResult:
        evidence = redactor.scrub(evidence)
        recommendation = {
            "confirmed": "record_finding with status 'confirmed' using this "
                         "evidence",
            "suspected": "record_finding with status 'suspected' and the "
                         "caveat",
            "no_issue": "do NOT record a finding — note the check as "
                        "performed in coverage",
            "inconclusive": "do NOT record a finding — fix the inputs or "
                            "report as not testable",
        }[v["verdict"]]
        return ToolResult(
            ok=True,
            summary=f"session_check[{check}] verdict: {v['verdict']} — "
                    f"{v['reason']}",
            data={"check": check, "identity": name, **v, **(extra or {}),
                  "evidence": evidence, "recommendation": recommendation},
        )
