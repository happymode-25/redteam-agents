"""Multi-identity session management (Phase 2.1).

One SessionManager holds a separate ScopedSession (cookie jar + headers)
per configured identity, so IDOR/BOLA testing can replay the same request
under two identities. All network traffic still flows through
ScopedSession: per-hop scope authorization + DNS resolve-and-pin apply to
login and verification requests exactly as to any other request.

Secret handling:
- credentials come from env vars referenced in config, resolved lazily at
  login time; missing vars fail with the VAR NAME (never a value);
- every resolved secret is registered with the redaction pass BEFORE any
  network call, so even error paths scrub it;
- summaries/status reports contain names, kinds and verification state
  only — never secret material.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import datetime, timezone

import requests

from .audit import AuditLog
from .config import IdentityConfig
from .http import ScopedHttpError, ScopedSession
from .redact import redactor
from .scope import Guard, ScopeViolation
from .tools.base import ToolError


@dataclass
class AuthSession:
    name: str
    kind: str
    verified: bool
    note: str
    established_at: str
    login_status: int | None = None

    def summary(self) -> dict:
        return {
            "identity": self.name,
            "kind": self.kind,
            "logged_in": True,
            "verified": self.verified,
            "established_at": self.established_at,
            "login_status": self.login_status,
            "note": self.note,
        }


def _resolve_env(env_name: str, identity: str) -> str:
    value = os.environ.get(env_name, "")
    if not value:
        raise ToolError(
            f"identity {identity!r}: environment variable {env_name} is not set"
        )
    return value


def _extract_bearer(resp: requests.Response) -> str:
    """Pull a bearer token out of a login response body, if one is there.
    Recognizes common shapes: {"authentication": {"token": ...}},
    {"token": ...}, {"access_token": ...}."""
    try:
        body = resp.json()
    except ValueError:
        return ""
    if not isinstance(body, dict):
        return ""
    auth = body.get("authentication")
    if isinstance(auth, dict) and isinstance(auth.get("token"), str):
        return auth["token"]
    for key in ("token", "access_token", "id_token", "jwt"):
        if isinstance(body.get(key), str):
            return body[key]
    return ""


class SessionManager:
    def __init__(self, identities: list[IdentityConfig], guard: Guard,
                 audit: AuditLog | None = None):
        self._idents = {i.name: i for i in identities}
        self._sessions: dict[str, ScopedSession] = {}
        self._meta: dict[str, AuthSession] = {}
        self.guard = guard
        self.audit = audit

    # ---- introspection -----------------------------------------------------

    def names(self) -> list[str]:
        return sorted(self._idents)

    def identity(self, name: str) -> IdentityConfig:
        """The configured identity (no secrets resolved) or ToolError."""
        ident = self._idents.get(name)
        if ident is None:
            raise ToolError(
                f"unknown identity {name!r}; configured: "
                f"{self.names() or 'none — set identities: in config'}"
            )
        return ident

    def status(self) -> list[dict]:
        out = []
        for name in sorted(self._idents):
            meta = self._meta.get(name)
            if meta:
                out.append(meta.summary())
            else:
                out.append({
                    "identity": name,
                    "kind": self._idents[name].kind,
                    "logged_in": False,
                    "verified": False,
                    "note": "not logged in",
                })
        return out

    def is_logged_in(self, name: str) -> bool:
        return name in self._sessions

    # ---- lifecycle ---------------------------------------------------------

    def login(self, name: str, preflight_cookie: str = "") -> AuthSession:
        """Establish a session. ``preflight_cookie`` (e.g. a pre-auth
        anonymous session cookie) is sent with the login request — used by
        the session-fixation probe."""
        ident = self._idents.get(name)
        if ident is None:
            raise ToolError(
                f"unknown identity {name!r}; configured: "
                f"{self.names() or 'none — set identities: in config'}"
            )
        self.logout(name)  # re-login always starts from a clean jar

        sess = ScopedSession(self.guard, timeout=15, max_redirects=5)
        verified = False
        status: int | None = None
        note = ""
        try:
            if preflight_cookie:
                redactor.register(preflight_cookie)
                sess.set_default_header("Cookie", preflight_cookie)
            if ident.kind == "form":
                user = _resolve_env(ident.username_env, name)
                password = _resolve_env(ident.password_env, name)
                redactor.register(user)
                redactor.register(password)
                payload = {
                    ident.username_field: user,
                    ident.password_field: password,
                    **ident.extra_fields,
                }
                resp = sess.request("POST", ident.login_url, data=payload)
                status = resp.status_code
                if resp.status_code >= 400:
                    raise ToolError(
                        f"form login got HTTP {resp.status_code}: "
                        f"{redactor.scrub(resp.text[:200])}"
                    )
                token = _extract_bearer(resp)
                if token:
                    redactor.register(token)
                    sess.set_default_header("Authorization", f"Bearer {token}")
                    note = "bearer token from login response stored"
                else:
                    note = "form login POST accepted; session cookie kept"
            elif ident.kind == "cookie":
                raw = _resolve_env(ident.cookie_env, name)
                redactor.register(raw)
                sess.set_default_header("Cookie", raw)
                note = "static cookie injected"
            elif ident.kind == "bearer":
                token = _resolve_env(ident.token_env, name)
                redactor.register(token)
                sess.set_default_header("Authorization", f"Bearer {token}")
                note = "static bearer token injected"
            elif ident.kind == "apikey":
                token = _resolve_env(ident.token_env, name)
                redactor.register(token)
                header = ident.header_name or "X-API-Key"
                sess.set_default_header(header, token)
                note = f"static {header} header injected"

            # any cookie the target set on us is live credential material —
            # register it so it can never appear verbatim in any output
            self._register_cookies(sess)

            if ident.verify_url:
                vr = sess.get(ident.verify_url)
                self._register_cookies(sess)
                if ident.verify_marker and ident.verify_marker in vr.text:
                    verified = True
                    note += f"; verified via GET {ident.verify_url}"
                else:
                    raise ToolError(
                        f"login verification FAILED for {name!r}: marker "
                        f"{ident.verify_marker!r} not found in "
                        f"GET {ident.verify_url} (HTTP {vr.status_code}) — "
                        "credentials or session are not valid"
                    )
            else:
                note += "; no verify_url configured — session assumed, NOT proven"

            meta = AuthSession(
                name=name,
                kind=ident.kind,
                verified=verified,
                note=note.strip("; "),
                established_at=datetime.now(timezone.utc).isoformat(),
                login_status=status,
            )
            self._sessions[name] = sess
            self._meta[name] = meta
            self._audit("session_login", ident, detail={
                "identity": name, "kind": ident.kind, "verified": verified,
                "login_status": status, "note": meta.note,
            })
            return meta
        except ScopeViolation:
            # out-of-scope login_url is a config/scope bug — abort loudly
            self._sessions.pop(name, None)
            self._meta.pop(name, None)
            self._audit("session_login_denied", ident,
                        detail={"identity": name, "reason": "scope violation"})
            raise
        except Exception as exc:
            # no half-open session ever survives a failed login, and every
            # failure surfaces to agents as ToolError (secret-scrubbed)
            self._sessions.pop(name, None)
            self._meta.pop(name, None)
            if not isinstance(exc, ToolError):
                exc = ToolError(
                    f"login for {name!r} failed: {type(exc).__name__}: "
                    f"{redactor.scrub(str(exc))}"
                )
            self._audit("session_login_failed", ident, detail={
                "identity": name,
                "error": redactor.scrub(str(exc))[:300],
            })
            raise exc

    def logout(self, name: str) -> bool:
        """Drop the session (jar + headers). Returns True if one existed."""
        existed = self._sessions.pop(name, None) is not None
        meta = self._meta.pop(name, None)
        if existed and self.audit:
            self.audit.record("session_logout", actor="session_manager",
                              detail={"identity": name})
        return existed

    def logout_all(self) -> int:
        count = sum(1 for n in list(self._sessions) if self.logout(n))
        return count

    def get_session(self, name: str) -> ScopedSession:
        sess = self._sessions.get(name)
        if sess is None:
            known = self.names()
            raise ToolError(
                f"identity {name!r} is not logged in — call session_login first"
                + (f" (configured identities: {known})" if known else "")
            )
        return sess

    def cookies(self, name: str) -> dict[str, str]:
        """Cookies visible to this identity's session: jar entries plus any
        cookie carried in the default Cookie header (pre-auth injections)."""
        sess = self.get_session(name)
        out = dict(sess.cookies())
        for part in sess.cookie_header().split(";"):
            key, _, value = part.partition("=")
            key, value = key.strip(), value.strip()
            if key and key not in out:
                out[key] = value
        return out

    @staticmethod
    def _register_cookies(sess: ScopedSession) -> None:
        for value in sess.cookies().values():
            if value:
                redactor.register(str(value))
        for part in sess.cookie_header().split(";"):
            value = part.partition("=")[2].strip()
            if value:
                redactor.register(value)

    def _audit(self, event: str, ident: IdentityConfig, detail: dict) -> None:
        if self.audit:
            self.audit.record(event, actor="session_manager",
                              target=ident.login_url or "(static credential)",
                              detail=detail)
