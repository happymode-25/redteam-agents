"""Scope-enforcing HTTP layer.

Fixes two MVP holes:
1. Redirect escape — requests follows redirects to ANY host, including
   out-of-scope ones. ScopedSession follows redirects manually and passes
   EVERY hop through Guard.authorize() + resolve().
2. DNS TOCTOU / rebinding — scope is checked on the hostname, then the tool
   resolves it again at connect time. ScopedSession resolves ONCE, authorizes
   the resolved IP, then pins it: socket.getaddrinfo for that exact hostname
   returns only the verified IP during the request (SNI and certificate
   validation stay bound to the real hostname).

The pin patch is process-global for the duration of one request — safe here
because agents execute sequentially; documented in README.
"""

from __future__ import annotations

import socket
from contextlib import contextmanager
from typing import Any
from urllib.parse import urljoin

import requests

from .scope import Guard, host_from_target

REDIRECT_CODES = {301, 302, 303, 307, 308}
DEFAULT_UA = "redteam-agents/0.1 (authorized assessment)"


class ScopedHttpError(Exception):
    """Raised when a scoped request cannot proceed (redirect cap, etc.)."""


@contextmanager
def _pinned_resolution(host: str, ip: str):
    """Make getaddrinfo(host) return only the verified IP inside this block."""
    if host == ip:  # already an IP literal — nothing to pin
        yield
        return
    real = socket.getaddrinfo

    def fake(node, port, *args, **kwargs):
        if node == host:
            family = socket.AF_INET6 if ":" in ip else socket.AF_INET
            return [(family, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (ip, port or 0))]
        return real(node, port, *args, **kwargs)

    socket.getaddrinfo = fake  # type: ignore[assignment]
    try:
        yield
    finally:
        socket.getaddrinfo = real  # type: ignore[assignment]


class ScopedSession:
    """requests-like interface where every hop and pin is scope-checked."""

    def __init__(
        self,
        guard: Guard,
        verify: bool = True,
        timeout: float = 15.0,
        max_redirects: int = 5,
        user_agent: str = DEFAULT_UA,
    ):
        self.guard = guard
        self.verify = verify
        self.timeout = timeout
        self.max_redirects = max_redirects
        self._session = requests.Session()
        self._session.headers["User-Agent"] = user_agent
        # Ignore env proxies: a proxy would receive the target hostname and
        # connect on our behalf, bypassing the resolve-and-pin guarantee.
        self._session.trust_env = False

    def get(self, url: str, **kwargs) -> requests.Response:
        return self.request("GET", url, **kwargs)

    def set_default_header(self, name: str, value: str) -> None:
        """Persistent header on every request of this session (auth tokens)."""
        self._session.headers[name] = value

    def cookies(self) -> dict[str, str]:
        """Current cookie jar as {name: value} (for session-lifecycle checks)."""
        return {c.name: c.value for c in self._session.cookies}

    def cookie_header(self) -> str:
        """The default Cookie header (static/pre-auth cookie injections)."""
        return self._session.headers.get("Cookie", "") or ""

    def default_headers(self) -> dict[str, str]:
        """Persistent default headers (auth tokens, CSRF, ...) — for seeding
        sibling sessions (race burst workers) with the same credentials."""
        return {k: v for k, v in self._session.headers.items()
                if k.lower() != "cookie"}

    def cookie_details(self) -> list[dict]:
        """Cookie jar with attributes (for session-hygiene checks)."""
        out: list[dict] = []
        for c in self._session.cookies:
            rest = getattr(c, "_rest", {}) or {}
            samesite = (c.get_nonstandard_attr("SameSite", None)
                        or rest.get("SameSite") or rest.get("samesite") or "")
            out.append({
                "name": c.name,
                "value": c.value,
                "domain": c.domain,
                "path": c.path,
                "secure": bool(c.secure),
                "httponly": bool(c.has_nonstandard_attr("HttpOnly")),
                "samesite": str(samesite or ""),
                "expires": c.expires,
            })
        return out

    def request(
        self,
        method: str,
        url: str,
        headers: dict | None = None,
        data: Any = None,
        json: Any = None,
        timeout: float | None = None,
        allow_redirects: bool = True,
        verify: bool | None = None,
    ) -> requests.Response:
        timeout = self.timeout if timeout is None else timeout
        verify = self.verify if verify is None else verify

        current = url
        history: list[requests.Response] = []
        for _hop in range(self.max_redirects + 1):
            self.guard.kill.check()
            host = host_from_target(current)
            self.guard.authorize(host)      # domain/CIDR policy per hop
            ip = self.guard.resolve(host)   # resolve ONCE, authorize IP, pin it

            with _pinned_resolution(host, ip):
                resp = self._session.request(
                    method,
                    current,
                    headers=headers,
                    data=data,
                    json=json,
                    timeout=timeout,
                    allow_redirects=False,
                    verify=verify,
                )

            if (
                allow_redirects
                and resp.status_code in REDIRECT_CODES
                and resp.headers.get("Location")
            ):
                history.append(resp)
                current = urljoin(current, resp.headers["Location"])
                if resp.status_code in (301, 302, 303) and method not in ("GET", "HEAD"):
                    method, data, json = "GET", None, None
                continue

            resp.history = history
            return resp

        raise ScopedHttpError(
            f"redirect chain exceeded {self.max_redirects} hops starting at {url}"
        )

    def close(self) -> None:
        self._session.close()
