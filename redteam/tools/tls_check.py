"""TLS configuration checks (catalog section 9 + 25).

Pure Python stdlib (ssl/socket) — no testssl.sh needed. Probes certificate
validity, hostname match, and protocol version support by attempting
handshakes at each TLS version. Connects only to the target's own port.
"""

from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone
from typing import Any

from ..scope import Guard
from .base import Tool, ToolError, ToolResult

VERSIONS = ["TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3"]
WEAK_VERSIONS = {"TLSv1", "TLSv1.1"}


def _handshake(host: str, ip: str, port: int, version: str | None) -> tuple[bool, str]:
    """Attempt a handshake at one TLS version, pinned to a verified IP."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    if version is not None:
        try:
            ctx.minimum_version = ssl.TLSVersion[version]
            ctx.maximum_version = ssl.TLSVersion[version]
        except KeyError:
            return False, "unknown version"
    try:
        with socket.create_connection((ip, port), timeout=8) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                return True, tls.version() or version or "?"
    except ssl.SSLError as exc:
        return False, f"SSL: {exc.strerror or exc}"
    except (socket.timeout, OSError) as exc:
        return False, str(exc)


def _cert_details(host: str, ip: str, port: int) -> dict[str, Any]:
    """Fetch the certificate WITH validation; report verify errors as findings."""
    out: dict[str, Any] = {}
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((ip, port), timeout=8) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                cert = tls.getpeercert()
    except ssl.SSLCertVerificationError as exc:
        out["verification_error"] = str(exc.verify_message or exc)
        return out
    except (socket.timeout, ssl.SSLError, OSError) as exc:
        out["fetch_error"] = str(exc)
        return out

    not_after = cert.get("notAfter")
    if not_after:
        expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(
            tzinfo=timezone.utc
        )
        out["not_after"] = expiry.isoformat()
        out["days_to_expiry"] = (expiry - datetime.now(timezone.utc)).days
    out["subject"] = dict(x[0] for x in cert.get("subject", ()))
    out["issuer"] = dict(x[0] for x in cert.get("issuer", ()))
    out["sans"] = [v for k, v in cert.get("subjectAltName", ())][:10]
    return out


class TlsCheckTool(Tool):
    name = "tls_check"
    description = (
        "Inspect TLS on an authorized host: certificate validity/hostname match, "
        "days to expiry, and which protocol versions the server accepts "
        "(TLS 1.0/1.1 enabled is a finding). Passive — one TCP connection per "
        "version to the host's own port."
    )
    parameters = {
        "type": "object",
        "properties": {
            "host": {"type": "string", "description": "Hostname or IP (must be in scope)"},
            "port": {"type": "integer", "description": "TLS port, default 443"},
        },
        "required": ["host"],
    }

    def __init__(self, guard: Guard):
        self.guard = guard

    def run(self, args: dict[str, Any]) -> ToolResult:
        host = str(args["host"]).strip()
        port = int(args.get("port") or 443)

        # Resolve ONCE, authorize the IP (anti-rebinding), pin all connections to it
        ip = self.guard.resolve(host)

        # Quick reachability check before version probing
        ok, detail = _handshake(host, ip, port, None)
        if not ok:
            if "timed out" in detail or "No such file" in detail:
                raise ToolError(f"no TLS service reachable at {host}:{port} ({detail})")
            return ToolResult(
                ok=True,
                summary=f"TLS handshake at {host}:{port} failed: {detail}",
                data={"host": host, "port": port, "handshake_error": detail},
            )

        support: dict[str, bool] = {}
        for version in VERSIONS:
            self.guard.kill.check()
            supported, _ = _handshake(host, ip, port, version)
            support[version] = supported

        cert = _cert_details(host, ip, port)

        issues: list[str] = []
        for weak in WEAK_VERSIONS:
            if support.get(weak):
                issues.append(f"{weak} is enabled on {host}:{port} (deprecated protocol)")
        days = cert.get("days_to_expiry")
        if isinstance(days, int) and days < 14:
            issues.append(f"certificate expires in {days} day(s)")
        if cert.get("verification_error"):
            issues.append(f"certificate validation failed: {cert['verification_error']}")
        if not any(support.values()):
            issues.append("no supported TLS version completed a handshake")

        data = {
            "host": host,
            "port": port,
            "version_support": support,
            "certificate": cert,
        }
        summary = (
            f"TLS at {host}:{port}: "
            + ", ".join(v for v, s in support.items() if s)
            + (f"; {len(issues)} issue(s)" if issues else "; no issues")
        )
        return ToolResult(ok=True, summary=summary, data=data)
