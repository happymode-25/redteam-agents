"""Process-level egress allowlist — the enforcement layer under ScopeGuard.

ScopeGuard is the *policy* (checked before a tool touches a target). This
module is the *enforcement*: once installed, every outbound connection made
by THIS process through the socket module must pass the same policy or it
never leaves the machine — even if a tool bug, a redirect, or a library
call bypasses Guard entirely.

What is checked:
  - socket.getaddrinfo / gethostbyname*  — hostname resolution (also the
    DNS query itself: unauthorized names are refused BEFORE any packet).
  - socket.socket.connect / connect_ex   — the actual TCP connect.
    IP-literal destinations must be in the scope CIDRs or in the set of
    IPs just resolved for an authorized hostname; hostname destinations
    are re-resolved through the policy and the address is rewritten to the
    verified IP (closes the resolve-then-connect TOCTOU window).
  - socket.socket.sendto                 — UDP egress to an IP.

What is allowed:
  - scope domains (same suffix rule as Guard.authorize) and their resolved
    IPs (cached with a TTL, refreshed on each authorized resolution);
  - scope CIDRs (IP targets);
  - the model API endpoints (llm.hosted/llm.local base_url hosts — the
    local Ollama backend included) and, when intel.enabled, the NVD/EPSS/
    CISA endpoints;
  - system proxy hosts when HTTP(S)_PROXY env vars are set (llm.py honors
    env proxies; ScopedSession deliberately does not).

Honest limits (documented, not hidden):
  - subprocess tools (nuclei, nmap, ...) are SEPARATE processes; this
    in-process patch cannot see them. The sandbox runner (sandbox.py) is
    the boundary for those; with safety.runner: local they share the host
    network. This firewall closes the gap for everything in the agent
    process itself (all Python HTTP: ScopedSession, LLM calls, intel).
  - C extensions that call libc connect() directly bypass the Python
    socket module. No current dependency does that.

Exceptions raised here are ScopeViolation subclasses, so every handler
treats an egress breach exactly like a scope breach: the agent loop turns
it into a denied "do not retry" observation (audit: tool_call/denied +
egress_blocked), and run_pipeline()/run_repo_scan() abort the run with
SystemExit(2) if it escapes the loop.
"""

from __future__ import annotations

import ipaddress
import socket
import threading
import time
from typing import Callable
from urllib.parse import urlparse
from urllib.request import getproxies

from .audit import AuditLog
from .config import AppConfig
from .hostnorm import normalize_domain_list, normalize_host
from .scope import ScopeViolation, _is_non_global

# Intel endpoints mirror tools/cve_lookup.py — imported so the allowlist
# cannot drift from the code that actually calls them.
from .tools.cve_lookup import EPSS_ENDPOINT, KEV_FEED, NVD_ENDPOINT

DEFAULT_TTL = 300.0


class EgressViolation(ScopeViolation):
    """Outbound connection refused by the process-level egress allowlist."""


def _host_of_url(url: str) -> str:
    return (urlparse(url).hostname or "").lower()


def _intel_hosts() -> set[str]:
    return {_host_of_url(u) for u in (NVD_ENDPOINT, KEV_FEED, EPSS_ENDPOINT)} - {""}


def _proxy_hosts() -> set[str]:
    out: set[str] = set()
    for value in getproxies().values():
        host = _host_of_url(value if "://" in value else f"http://{value}")
        if host:
            out.add(host)
    return out


class EgressFirewall:
    """Socket-layer allowlist. Installed by run_pipeline()/run_repo_scan()."""

    def __init__(
        self,
        *,
        scope_domains: list[str],
        allow_cidrs: list[str],
        allow_subdomains: bool = True,
        allow_private: bool = False,
        extra_hosts: set[str] | None = None,
        audit: AuditLog | None = None,
        ttl: float = DEFAULT_TTL,
        clock: Callable[[], float] = time.monotonic,
    ):
        self.scope_domains = normalize_domain_list(list(scope_domains))
        try:
            self.networks = [ipaddress.ip_network(c, strict=False) for c in allow_cidrs]
        except ValueError as exc:
            raise EgressViolation(f"invalid CIDR in scope config: {exc}") from exc
        self.allow_subdomains = allow_subdomains
        self.allow_private = allow_private
        self.extra_hosts = {h.lower().rstrip(".") for h in (extra_hosts or set()) if h}
        self.audit = audit
        self.ttl = ttl
        self._now = clock
        self._ips: dict[str, float] = {}       # resolved IP -> expiry
        self._lock = threading.Lock()
        self._installed = False
        self._originals: dict[str, object] = {}
        self._patched: dict[str, object] = {}

    # ------------------------------------------------------------------ #
    # policy
    # ------------------------------------------------------------------ #

    def _host_allowed(self, host: str) -> bool:
        for domain in self.scope_domains:
            if host == domain or (self.allow_subdomains and host.endswith("." + domain)):
                return True
        return host in self.extra_hosts

    def _ip_in_cidrs(self, ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
        return any(ip in net for net in self.networks)

    def _cache(self, ips: set[str]) -> None:
        expiry = self._now() + self.ttl
        with self._lock:
            for ip in ips:
                self._ips[ip] = expiry

    def _ip_cached(self, ip: str) -> bool:
        with self._lock:
            expiry = self._ips.get(ip)
            if expiry is not None and expiry > self._now():
                return True
            self._ips.pop(ip, None)
            return False

    def _audit_block(self, target: str, reason: str, **detail) -> None:
        if self.audit is not None:
            self.audit.record("egress_blocked", actor="egress_firewall",
                              target=target, decision="denied",
                              detail={"reason": reason, **detail})

    # ------------------------------------------------------------------ #
    # checks (each raises EgressViolation — a ScopeViolation — on block)
    # ------------------------------------------------------------------ #

    def check_host(self, node: str) -> str:
        """Hostname policy check; returns the normalized host.

        IP literals fall through to check_ip and return as-is.
        """
        try:
            host = normalize_host(node)
        except ValueError as exc:
            self._audit_block(node, "unparseable")
            raise EgressViolation(f"egress blocked: cannot parse host {node!r}") from exc
        try:
            ipaddress.ip_address(host)
        except ValueError:
            pass
        else:
            self.check_ip(host)
            return host
        if not self._host_allowed(host):
            self._audit_block(host, "hostname outside allowlist")
            raise EgressViolation(
                f"egress blocked: {host} is not in the engagement allowlist "
                "(scope domains + model/intel endpoints only)"
            )
        return host

    def check_ip(self, ip: str) -> None:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError as exc:
            self._audit_block(ip, "unparseable ip")
            raise EgressViolation(f"egress blocked: cannot parse IP {ip!r}") from exc
        if self._ip_cached(ip):
            return
        if str(addr) in self.extra_hosts:
            # base_url given as a raw IP (e.g. a self-hosted backend at
            # http://127.0.0.1:11434) — operator-configured endpoint.
            return
        if self._ip_in_cidrs(addr):
            if _is_non_global(addr) and not self.allow_private:
                # Matches Guard.authorize: a CIDR match alone does not
                # license private targets when the operator forbade them.
                self._audit_block(ip, "private/reserved address in CIDR",
                                  note="allow_private is false")
                raise EgressViolation(
                    f"egress blocked: {ip} is inside an allowlisted CIDR but "
                    "is private/reserved and allow_private is false"
                )
            return
        self._audit_block(ip, "IP outside scope CIDRs and not freshly resolved")
        raise EgressViolation(
            f"egress blocked: {ip} is outside every scope CIDR and was not "
            "resolved from an authorized hostname"
        )

    def _usable(self, host: str, ips: list[str]) -> list[str]:
        """Answers acceptable under policy, in sorted order.

        Extra hosts (model/intel endpoints) and anything under
        allow_private keep their private answers; scope hosts only
        keep global answers — a scope name re-resolving to a private
        IP is exactly the rebinding shape Guard.resolve rejects.
        """
        exempt = self._extra(host) or self.allow_private
        out: list[str] = []
        for ip in ips:
            try:
                addr = ipaddress.ip_address(ip)
            except ValueError:
                continue
            if not exempt and _is_non_global(addr):
                continue
            out.append(ip)
        return out

    def check_connect(self, host: str) -> str:
        """Connect-time check; returns the IP to actually connect to.

        Hostnames are resolved through the ORIGINAL getaddrinfo (policy
        already approved the name), filtered through the same usable-answer
        rule as getaddrinfo caching, and the verified IP is returned so the
        caller can pin the address — no rebinding gap.
        """
        try:
            addr = ipaddress.ip_address(host)
        except ValueError:
            addr = None
        if addr is not None:
            self.check_ip(str(addr))
            return str(addr)

        # Hostname at connect time (bypassed getaddrinfo): resolve via policy.
        host = self.check_host(host)
        infos = _ORIGINAL_GETADDRINFO(host, None, proto=socket.IPPROTO_TCP)
        ips = sorted({info[4][0] for info in infos})
        if not ips:
            raise EgressViolation(f"egress blocked: {host} resolved to no addresses")
        usable = self._usable(host, ips)
        if not usable:
            self._audit_block(host, "all answers private/reserved", ips=ips,
                              note="possible DNS rebinding")
            raise EgressViolation(
                f"egress blocked: {host} resolves only to private/reserved "
                f"addresses ({', '.join(ips)}) and allow_private is false"
            )
        self._cache(set(usable))
        return usable[0]

    def _extra(self, host: str) -> bool:
        return host in self.extra_hosts

    # ------------------------------------------------------------------ #
    # socket patches
    # ------------------------------------------------------------------ #

    def _patched_getaddrinfo(self, node, port, *args, **kwargs):
        if isinstance(node, bytes):
            node = node.decode("utf-8", "replace")
        is_name = False
        if node:
            try:
                ipaddress.ip_address(str(node))
            except ValueError:
                is_name = True
        if is_name:
            # Hostname: refuse BEFORE the DNS query if out of policy.
            name = self.check_host(str(node))
        # IP literals are neither checked nor cached here: no packet leaves
        # for a numeric answer, this path also serves bind(), and the
        # authoritative enforcement for numeric destinations is connect().
        result = _ORIGINAL_GETADDRINFO(node, port, *args, **kwargs)
        if is_name:
            answers = [info[4][0] for info in result]
            self._cache(set(self._usable(name, answers)))
        return result

    def _patched_connect(self, sock, address):
        if getattr(sock, "family", None) not in (socket.AF_INET, socket.AF_INET6):
            return _ORIGINAL_CONNECT(sock, address)  # non-IP socket: not egress
        if not isinstance(address, tuple):        # not a sockaddr — let CPython raise
            return _ORIGINAL_CONNECT(sock, address)
        host = address[0]
        if isinstance(host, bytes):
            host = host.decode("utf-8", "replace")
        ip = self.check_connect(str(host))
        pinned = (ip, *address[1:])
        return _ORIGINAL_CONNECT(sock, pinned)

    def _patched_connect_ex(self, sock, address):
        if getattr(sock, "family", None) not in (socket.AF_INET, socket.AF_INET6):
            return _ORIGINAL_CONNECT_EX(sock, address)
        if not isinstance(address, tuple):
            return _ORIGINAL_CONNECT_EX(sock, address)
        host = address[0]
        if isinstance(host, bytes):
            host = host.decode("utf-8", "replace")
        ip = self.check_connect(str(host))
        return _ORIGINAL_CONNECT_EX(sock, (ip, *address[1:]))

    def _patched_sendto(self, sock, *args):
        if getattr(sock, "family", None) not in (socket.AF_INET, socket.AF_INET6):
            return _ORIGINAL_SENDTO(sock, *args)
        if not args:
            return _ORIGINAL_SENDTO(sock, *args)   # let CPython raise TypeError
        address = args[-1]                         # sendto(data, [flags,] address)
        if isinstance(address, tuple):
            host = address[0]
            if isinstance(host, bytes):
                host = host.decode("utf-8", "replace")
            self.check_connect(str(host))
        return _ORIGINAL_SENDTO(sock, *args)

    def _patched_gethostbyname(self, host):
        self.check_host(host)
        return _ORIGINAL_GETHOSTBYNAME(host)

    def _patched_gethostbyname_ex(self, host):
        name = self.check_host(host)
        result = _ORIGINAL_GETHOSTBYNAME_EX(host)
        try:
            answers = list(result[2])
        except (IndexError, TypeError):
            return result
        self._cache(set(self._usable(name, answers)))
        return result

    # ------------------------------------------------------------------ #
    # lifecycle
    # ------------------------------------------------------------------ #

    def install(self) -> str:
        """Patch the socket module (idempotent). Call before any traffic."""
        global _ACTIVE
        if self._installed:
            return "already installed"
        if _ACTIVE is not None and _ACTIVE is not self:
            _ACTIVE.uninstall()       # hand over cleanly; never stack patches
        self._originals = {
            "getaddrinfo": socket.getaddrinfo,
            "gethostbyname": socket.gethostbyname,
            "gethostbyname_ex": socket.gethostbyname_ex,
            "connect": socket.socket.connect,
            "connect_ex": socket.socket.connect_ex,
            "sendto": socket.socket.sendto,
        }
        # Class-level patches MUST be plain functions (a bound method stored
        # as a class attribute is not re-bound to the socket instance, so
        # sock.connect(addr) would lose the socket argument); module-level
        # patches may be bound methods. Every patched object is stored here
        # BY IDENTITY: re-reading self._patched_getaddrinfo later creates a
        # NEW bound method each access, so `is` against a fresh access would
        # never match and uninstall() would silently restore nothing.
        self._patched = {
            "getaddrinfo": self._patched_getaddrinfo,
            "gethostbyname": self._patched_gethostbyname,
            "gethostbyname_ex": self._patched_gethostbyname_ex,
            "connect": lambda sock, address: self._patched_connect(sock, address),
            "connect_ex": lambda sock, address: self._patched_connect_ex(sock, address),
            "sendto": lambda sock, *args: self._patched_sendto(sock, *args),
        }
        socket.getaddrinfo = self._patched["getaddrinfo"]          # type: ignore[assignment]
        socket.gethostbyname = self._patched["gethostbyname"]      # type: ignore[assignment]
        socket.gethostbyname_ex = self._patched["gethostbyname_ex"]  # type: ignore[assignment]
        socket.socket.connect = self._patched["connect"]           # type: ignore[assignment]
        socket.socket.connect_ex = self._patched["connect_ex"]      # type: ignore[assignment]
        socket.socket.sendto = self._patched["sendto"]             # type: ignore[assignment]
        self._installed = True
        _ACTIVE = self
        return "installed"

    def uninstall(self) -> None:
        """Restore the socket module (only where we are still the patcher).

        Identity comparisons use the exact objects stored at install time.
        If another layer (e.g. http.py's per-request pin) currently owns a
        slot, we leave it alone — never clobber a foreign patch; that layer
        restores on its way out (worst case our patch lingers: fail-closed).
        """
        global _ACTIVE
        if not self._installed:
            return
        if socket.getaddrinfo is self._patched.get("getaddrinfo"):
            socket.getaddrinfo = self._originals["getaddrinfo"]      # type: ignore[assignment]
        if socket.gethostbyname is self._patched.get("gethostbyname"):
            socket.gethostbyname = self._originals["gethostbyname"]  # type: ignore[assignment]
        if socket.gethostbyname_ex is self._patched.get("gethostbyname_ex"):
            socket.gethostbyname_ex = self._originals["gethostbyname_ex"]  # type: ignore[assignment]
        if socket.socket.connect is self._patched.get("connect"):
            socket.socket.connect = self._originals["connect"]       # type: ignore[assignment]
        if socket.socket.connect_ex is self._patched.get("connect_ex"):
            socket.socket.connect_ex = self._originals["connect_ex"]  # type: ignore[assignment]
        if socket.socket.sendto is self._patched.get("sendto"):
            socket.socket.sendto = self._originals["sendto"]         # type: ignore[assignment]
        self._installed = False
        if _ACTIVE is self:
            _ACTIVE = None

    def __enter__(self) -> "EgressFirewall":
        self.install()
        return self

    def __exit__(self, *exc) -> None:
        self.uninstall()

    # ------------------------------------------------------------------ #
    # construction from platform config
    # ------------------------------------------------------------------ #

    @classmethod
    def from_config(cls, cfg: AppConfig, audit: AuditLog | None = None) -> "EgressFirewall":
        """Build the firewall from the engagement config.

        Allowlist = scope domains/CIDRs + model API hosts (both backends,
        including the local Ollama) + intel endpoints when intel.enabled +
        any system proxy hosts (llm.py honors env proxies).
        """
        extra = {
            _host_of_url(cfg.llm.hosted.base_url),
            _host_of_url(cfg.llm.local.base_url),
        } - {""}
        if cfg.intel.enabled:
            extra |= _intel_hosts()
        extra |= _proxy_hosts()
        return cls(
            scope_domains=list(cfg.scope.allow_domains),
            allow_cidrs=list(cfg.scope.allow_cidrs),
            allow_subdomains=cfg.scope.allow_subdomains,
            allow_private=cfg.scope.allow_private,
            extra_hosts=extra,
            audit=audit,
        )

    def describe(self) -> str:
        extras = ", ".join(sorted(self.extra_hosts))
        return (f"egress firewall: domains={self.scope_domains} "
                f"cidrs={[str(n) for n in self.networks]} extras=[{extras}]")


# Module-level state: the currently installed firewall (None when off).
_ACTIVE: EgressFirewall | None = None

# Original socket functions, captured at import so patched helpers can call
# the real implementations without recursion.
_ORIGINAL_GETADDRINFO = socket.getaddrinfo
_ORIGINAL_GETHOSTBYNAME = socket.gethostbyname
_ORIGINAL_GETHOSTBYNAME_EX = socket.gethostbyname_ex
_ORIGINAL_CONNECT = socket.socket.connect
_ORIGINAL_CONNECT_EX = socket.socket.connect_ex
_ORIGINAL_SENDTO = socket.socket.sendto


def set_audit(audit: AuditLog | None) -> None:
    """Attach the run's audit log to the active firewall (no-op when off)."""
    if _ACTIVE is not None:
        _ACTIVE.audit = audit


def active() -> EgressFirewall | None:
    return _ACTIVE
