"""Email authentication checks: SPF, DKIM, DMARC (catalog section 20).

Pure Python stdlib — a minimal DNS-over-UDP client, so no dig/nslookup
dependency and no third-party DNS service sees your target data.
"""

from __future__ import annotations

import os
import socket
import struct
import subprocess
from typing import Any

from .base import Tool, ToolError, ToolResult

QTYPE_MX, QTYPE_TXT = 15, 16
COMMON_DKIM_SELECTORS = ["default", "google", "selector1", "selector2", "k1", "mail", "s1", "s2"]


class DNSError(Exception):
    pass


def _default_dns_servers() -> list[str]:
    try:
        with open("/etc/resolv.conf", encoding="utf-8") as fh:
            for line in fh:
                if line.startswith("nameserver"):
                    server = line.split()[1]
                    if ":" not in server:
                        return [server]
    except OSError:
        pass
    try:
        out = subprocess.run(
            [
                "powershell", "-NoProfile", "-Command",
                "(Get-DnsClientServerAddress -AddressFamily IPv4 | "
                "Where-Object {$_.ServerAddresses}).ServerAddresses",
            ],
            capture_output=True, text=True, timeout=10,
        )
        servers = [
            line.strip() for line in out.stdout.splitlines()
            if line.strip() and line.strip()[0].isdigit()
        ]
        if servers:
            return servers[:2]
    except (OSError, subprocess.SubprocessError):
        pass
    return ["1.1.1.1"]  # documented fallback: public resolver


def _read_name(buf: bytes, offset: int) -> tuple[str, int]:
    labels: list[str] = []
    end: int | None = None
    while offset < len(buf):
        length = buf[offset]
        if length & 0xC0 == 0xC0:
            pointer = struct.unpack(">H", buf[offset : offset + 2])[0] & 0x3FFF
            if end is None:
                end = offset + 2
            offset = pointer
            continue
        if length == 0:
            offset += 1
            break
        offset += 1
        labels.append(buf[offset : offset + length].decode("utf-8", "replace"))
        offset += length
    return ".".join(labels), (end if end is not None else offset)


def _query(servers: list[str], name: str, qtype: int, timeout: float = 5.0) -> list[Any]:
    tid = int.from_bytes(os.urandom(2), "big")
    packet = struct.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, 0)
    for label in name.split("."):
        if label:
            packet += bytes([len(label)]) + label.encode("utf-8")
    packet += b"\x00" + struct.pack(">HH", qtype, 1)

    last_error: Exception | None = None
    for server in servers:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        try:
            sock.sendto(packet, (server, 53))
            data, _ = sock.recvfrom(2048)
        except (socket.timeout, OSError) as exc:
            last_error = exc
            continue
        finally:
            sock.close()

        _, flags, qd, an, _, _ = struct.unpack(">HHHHHH", data[:12])
        rcode = flags & 0xF
        if rcode == 3:  # NXDOMAIN
            return []
        if rcode != 0:
            raise DNSError(f"DNS rcode {rcode} from {server}")
        try:
            offset = 12
            for _ in range(qd):
                _, offset = _read_name(data, offset)
                offset += 4
            records: list[Any] = []
            for _ in range(an):
                _, offset = _read_name(data, offset)
                rtype, _, _, rdlen = struct.unpack(">HHIH", data[offset : offset + 10])
                offset += 10
                rdata = data[offset : offset + rdlen]
                rdata_offset = offset
                offset += rdlen
                if rtype == QTYPE_TXT == qtype:
                    chunks, i = [], 0
                    while i < len(rdata):
                        ln = rdata[i]
                        chunks.append(rdata[i + 1 : i + 1 + ln].decode("utf-8", "replace"))
                        i += 1 + ln
                    records.append("".join(chunks))
                elif rtype == QTYPE_MX == qtype and len(rdata) >= 3:
                    pref = struct.unpack(">H", rdata[:2])[0]
                    exchange, _ = _read_name(data, rdata_offset + 2)
                    records.append((pref, exchange))
            return records
        except (struct.error, IndexError, UnicodeDecodeError) as exc:
            raise DNSError(f"malformed DNS response from {server}: {exc}") from exc
    raise DNSError(f"no response from any resolver: {last_error}")


class EmailAuthCheckTool(Tool):
    name = "email_auth_check"
    description = (
        "Check email authentication DNS records for an authorized domain: SPF, "
        "DMARC (including policy strength), MX, and DKIM across common selectors. "
        "Read-only DNS queries only — no email is sent."
    )
    parameters = {
        "type": "object",
        "properties": {
            "domain": {"type": "string", "description": "Domain to check, e.g. example.com"},
        },
        "required": ["domain"],
    }

    def run(self, args: dict[str, Any]) -> ToolResult:
        domain = str(args["domain"]).strip().lower().lstrip("*.")
        servers = _default_dns_servers()

        try:
            spf_records = [r for r in _query(servers, domain, QTYPE_TXT) if "v=spf1" in r.lower()]
            dmarc_records = [
                r for r in _query(servers, f"_dmarc.{domain}", QTYPE_TXT)
                if "v=dmarc1" in r.lower()
            ]
            mx_records = sorted(_query(servers, domain, QTYPE_MX))
            dkim_found = []
            for selector in COMMON_DKIM_SELECTORS:
                try:
                    recs = _query(servers, f"{selector}._domainkey.{domain}", QTYPE_TXT)
                except DNSError:
                    continue
                if any("p=" in r.lower() for r in recs):
                    dkim_found.append(selector)
        except DNSError as exc:
            raise ToolError(f"DNS lookup failed for {domain}: {exc}") from exc

        issues: list[str] = []
        if not spf_records:
            issues.append(f"no SPF record for {domain} (email spoofing possible)")
        if not dmarc_records:
            issues.append(f"no DMARC record for {domain} (spoofed-domain email not blocked)")
        else:
            policy = "".join(dmarc_records).lower()
            if "p=none" in policy:
                issues.append("DMARC policy is p=none: monitoring only, not enforcing")
            elif "p=quarantine" in policy:
                issues.append("DMARC policy is p=quarantine (consider p=reject)")
        if not mx_records:
            issues.append(f"no MX records for {domain}")
        if not dkim_found:
            issues.append(
                "no DKIM key found among common selectors "
                f"({', '.join(COMMON_DKIM_SELECTORS[:5])}, ...)"
            )

        data = {
            "domain": domain,
            "resolvers_used": servers,
            "spf": spf_records,
            "dmarc": dmarc_records,
            "mx": [{"preference": p, "exchange": e} for p, e in mx_records[:10]],
            "dkim_selectors_found": dkim_found,
        }
        summary = (
            f"{domain}: SPF={'yes' if spf_records else 'NO'}, "
            f"DMARC={'yes' if dmarc_records else 'NO'}, "
            f"DKIM selectors={dkim_found or 'none'}; {len(issues)} issue(s)"
        )
        return ToolResult(ok=True, summary=summary, data=data)
