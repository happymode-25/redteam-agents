"""Scope enforcement — the hard safety boundary.

Plain code the LLM never sees or influences. Every tool execution passes
through ScopeGuard.run(): kill switch -> target authorization -> rate limit
-> execution. A prompt injection inside tool output cannot widen scope,
because authorization happens after the model has spoken and against the
literal target string the tool is about to touch.

resolve() closes the DNS TOCTOU hole: it resolves a hostname ONCE, rejects
private/reserved addresses (unless allow_private), and returns the verified
IP for connection pinning (see http.py).
"""

from __future__ import annotations

import ipaddress
import socket
import threading
import time
from collections import deque
from dataclasses import dataclass
from pathlib import Path
from typing import Callable
from urllib.parse import urlparse

from .audit import AuditLog
from .config import ScopeConfig
from .hostnorm import normalize_domain_list, normalize_host


class ScopeViolation(Exception):
    """Raised when a target falls outside the authorization boundary."""


class KillSwitchEngaged(Exception):
    """Raised when the kill switch has been tripped."""


class KillSwitch:
    """Stops the run via Ctrl+C (handled in main) or a sentinel file."""

    def __init__(self, path: Path):
        self.path = path
        self._tripped = False
        self._lock = threading.Lock()

    def trip(self) -> None:
        with self._lock:
            self._tripped = True

    def check(self) -> None:
        with self._lock:
            tripped = self._tripped
        if tripped or self.path.exists():
            raise KillSwitchEngaged("kill switch engaged - stopping execution")


class RateLimiter:
    """Per-host token bucket: N requests per minute per host."""

    def __init__(self, per_min: int):
        self.per_min = per_min
        self._hits: dict[str, deque[float]] = {}
        self._lock = threading.Lock()

    def wait(self, host: str) -> None:
        if self.per_min <= 0:
            return
        window = 60.0
        while True:
            with self._lock:
                now = time.monotonic()
                q = self._hits.setdefault(host, deque())
                while q and now - q[0] > window:
                    q.popleft()
                if len(q) < self.per_min:
                    q.append(now)
                    return
                sleep_for = window - (now - q[0]) + 0.05
            time.sleep(min(sleep_for, 5.0))


def host_from_target(target: str) -> str:
    """Extract and canonicalize the host from a URL, host:port, or bare host/IP."""
    t = target.strip()
    if "://" in t:
        parsed = urlparse(t)
        if not parsed.hostname:
            raise ScopeViolation(f"cannot parse host from target: {target!r}")
        raw = parsed.hostname
    elif t.startswith("["):
        end = t.find("]")
        if end == -1:
            raise ScopeViolation(f"malformed IPv6 target: {target!r}")
        raw = t[1:end]
    elif t.count(":") == 1:
        raw = t.split(":", 1)[0]
    else:
        raw = t
    try:
        return normalize_host(raw)
    except ValueError as exc:
        raise ScopeViolation(f"cannot parse host from target: {target!r}") from exc


def _is_non_global(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return bool(
        ip.is_private or ip.is_loopback or ip.is_link_local
        or ip.is_reserved or ip.is_multicast or ip.is_unspecified
    )


@dataclass
class Guard:
    cfg: ScopeConfig
    kill: KillSwitch
    limiter: RateLimiter
    audit: AuditLog | None = None

    def __post_init__(self) -> None:
        # Canonicalize the allowlist here (not just at config load) so every
        # construction path compares target and allowlist in the same form.
        self.cfg = ScopeConfig(
            allow_domains=normalize_domain_list(self.cfg.allow_domains),
            allow_cidrs=list(self.cfg.allow_cidrs),
            allow_subdomains=self.cfg.allow_subdomains,
            allow_private=self.cfg.allow_private,
            rate_limit_per_host_per_min=self.cfg.rate_limit_per_host_per_min,
        )

    @classmethod
    def from_config(cls, cfg: ScopeConfig, artifacts_dir: Path,
                    audit: AuditLog | None = None) -> "Guard":
        return cls(
            cfg=cfg,
            kill=KillSwitch(artifacts_dir / "KILLSWITCH"),
            limiter=RateLimiter(cfg.rate_limit_per_host_per_min),
            audit=audit,
        )

    def _audit(self, event: str, target: str, decision: str = "",
               detail: dict | None = None) -> None:
        if self.audit is not None:
            self.audit.record(event, actor="scope_guard", target=target,
                              decision=decision, detail=detail)

    def authorize(self, target: str) -> str:
        """Return the normalized host if in scope, else raise ScopeViolation."""
        host = host_from_target(target)

        try:
            networks = [ipaddress.ip_network(c, strict=False) for c in self.cfg.allow_cidrs]
        except ValueError as exc:
            raise ScopeViolation(f"invalid CIDR in scope config: {exc}") from exc

        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            ip = None

        if ip is not None:
            if not networks:
                self._audit("scope_denied", host, "denied",
                            {"reason": "IP target but no CIDRs allowlisted"})
                raise ScopeViolation(f"IP target {host} not in scope: no CIDRs allowlisted")
            if not any(ip in net for net in networks):
                self._audit("scope_denied", host, "denied",
                            {"reason": "outside allowlisted CIDRs"})
                raise ScopeViolation(f"IP {host} is outside every allowlisted CIDR")
            if _is_non_global(ip) and not self.cfg.allow_private:
                self._audit("scope_denied", host, "denied",
                            {"reason": "private/reserved address"})
                raise ScopeViolation(
                    f"{host} is a private/reserved address and allow_private is false"
                )
            self._audit("scope_allowed", host, "allowed", {"kind": "ip"})
            return str(ip)

        for domain in self.cfg.allow_domains:
            if host == domain or (self.cfg.allow_subdomains and host.endswith("." + domain)):
                self._audit("scope_allowed", host, "allowed",
                            {"kind": "domain", "matched": domain})
                return host
        self._audit("scope_denied", host, "denied", {"reason": "not in allowlist"})
        raise ScopeViolation(f"host {host} is not in the scope allowlist")

    def resolve(self, host: str) -> str:
        """Resolve host once, reject non-global answers, return the verified IP.

        Closes the DNS-rebinding window: callers connect to THIS IP (pinned),
        never resolving the name again at connect time.
        """
        self.kill.check()
        try:
            infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
        except socket.gaierror as exc:
            self._audit("resolve_failed", host, "error", {"error": str(exc)})
            raise ScopeViolation(f"cannot resolve {host}: {exc}") from exc

        ips = sorted({info[4][0] for info in infos})
        if not ips:
            raise ScopeViolation(f"no addresses returned for {host}")

        chosen = None
        for candidate in ips:
            ip = ipaddress.ip_address(candidate)
            if _is_non_global(ip) and not self.cfg.allow_private:
                continue
            chosen = candidate
            break

        if chosen is None:
            self._audit("resolve_denied", host, "denied",
                        {"ips": ips, "reason": "all answers private/reserved"})
            raise ScopeViolation(
                f"{host} resolves only to private/reserved addresses ({', '.join(ips)}); "
                "possible DNS rebinding (set allow_private for authorized internal tests)"
            )

        self._audit("resolve_allowed", host, "allowed", {"ips": ips, "chosen": chosen})
        return chosen

    def run(self, target: str, fn: Callable, *args, **kwargs):
        """Authorize + rate-limit + kill-switch-check, then execute fn."""
        self.kill.check()
        host = self.authorize(target)
        self.limiter.wait(host)
        self.kill.check()
        return fn(*args, **kwargs)
