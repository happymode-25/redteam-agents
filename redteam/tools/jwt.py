"""JWT static checks (Phase 2.2 — session/authentication hardening).

Pure-local analysis of a captured JSON Web Token: decode header/claims
(base64url + json, stdlib only) and run deterministic checks:

  confirmed   — HS* signature verifies against a well-known/guessable
                secret (anyone can forge tokens; CWE-798), or the
                base64-readable claims carry sensitive-named fields with
                values (JWT payloads are NOT encrypted; CWE-200).
  suspected   — alg "none" (unsigned token — acceptance by the server is
                NOT tested here; CWE-347), missing exp (no enforced
                expiry; CWE-613), or a > 30-day validity window.
  no_issue    — expired token (if the server still accepts it, that is a
                server-side finding testable with the session tools), or
                none of the static checks hit.

What this tool does NOT do (stated honestly in the report): it never
talks to the target, never replays the token, and cannot verify RS*/ES*
signatures (asymmetric keys) — those show up as structure-only results.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import time
from typing import Any

from ..redact import redactor
from .base import Tool, ToolError, ToolResult
from .schema import EXCLUDE_KEY_RE, SENSITIVE_KEY_RE

# Well-known/guessable HS256 secrets (the jwt_tool "default wordlist"
# idea, kept small — this is a fast deterministic probe, not a cracker).
COMMON_SECRETS = (
    "secret", "password", "changeme", "123456", "12345678", "qwerty",
    "jwt_secret", "jwt-secret", "supersecret", "mysecret", "secretkey",
    "your-256-bit-secret", "keyboard cat", "private", "key", "test",
    "admin", "letmein", "hunter2", "correcthorsebatterystaple",
    "default", "example", "development", "production", "auth", "token",
    "pass", "foo", "bar", "redteam", "changeme123", "secret123",
    "hs256", "hmac", "shared-secret", "my-secret-key",
)

LONG_LIVED_DAYS = 30
SENSITIVE_CLAIM_DEPTH = 6

# Headers that let the TOKEN influence which key verifies it (static signals
# of key-confusion / kid-injection surface — server-side acceptance is NOT
# tested by this tool; every hit is reported as 'suspected').
KEY_CONTROL_HEADERS = {
    "jwk": ("token embeds its own verification key (jwk header) — if the "
            "server trusts it, any token can self-verify", "CWE-347"),
    "jku": ("token names a JWKS URL (jku) the server may fetch key material "
            "from — key injection / SSRF surface", "CWE-347"),
    "x5u": ("token names a certificate URL (x5u) the server may fetch — key "
            "injection / SSRF surface", "CWE-347"),
    "x5c": ("token carries its own certificate chain (x5c) — key material "
            "controlled by the token", "CWE-347"),
}
KID_TRAVERSAL_RE = re.compile(r"(\.\.[/\\]|\.\.$|/etc/passwd|/proc/self)", re.I)
KID_SQL_RE = re.compile(r"('|--|;|/\*|\bunion\b|\bor\b)", re.I)
KID_URL_RE = re.compile(r"^https?://", re.I)


def b64url_decode(segment: str) -> bytes:
    seg = segment.strip()
    seg += "=" * (-len(seg) % 4)
    return base64.urlsafe_b64decode(seg.encode("ascii"))


def b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def parse_jwt(token: str) -> tuple[dict, dict, str]:
    """Split and decode a JWT. Returns (header, claims, signature_segment).

    Raises ToolError with an actionable message on anything malformed —
    a broken token is the caller's input problem, not a finding.
    """
    tok = (token or "").strip()
    if tok.lower().startswith("bearer "):
        tok = tok[7:].strip()
    parts = tok.split(".")
    if len(parts) not in (2, 3):
        raise ToolError(
            f"not a JWT: expected 2-3 dot-separated base64url segments, "
            f"got {len(parts)}"
        )
    try:
        header = json.loads(b64url_decode(parts[0]))
        claims = json.loads(b64url_decode(parts[1]))
    except (ValueError, json.JSONDecodeError) as exc:
        raise ToolError(f"JWT header/claims do not decode to JSON: {exc}")
    if not isinstance(header, dict) or not isinstance(claims, dict):
        raise ToolError("JWT header and claims must both be JSON objects")
    signature = parts[2] if len(parts) == 3 else ""
    return header, claims, signature


def verify_weak_secret(signing_input: str, signature: str,
                       alg: str,
                       secrets: tuple[str, ...] = COMMON_SECRETS) -> str | None:
    """Try well-known secrets against an HS* signature (constant-time eq).
    Returns the matching secret, or None. Asymmetric algs are skipped."""
    if not alg.upper().startswith("HS") or not signature:
        return None
    try:
        sig_bytes = b64url_decode(signature)
    except ValueError:
        return None
    for secret in secrets:
        digest = hmac.new(secret.encode("utf-8"),
                          signing_input.encode("ascii"),
                          hashlib.sha256).digest()
        if hmac.compare_digest(digest, sig_bytes):
            return secret
    return None


def _sensitive_claims(claims: dict, prefix: str = "",
                      depth: int = 0) -> list[str]:
    out: list[str] = []
    if depth > SENSITIVE_CLAIM_DEPTH:
        return out
    for key, value in claims.items():
        path = f"{prefix}.{key}" if prefix else str(key)
        if isinstance(value, dict):
            out += _sensitive_claims(value, path, depth + 1)
        elif EXCLUDE_KEY_RE.search(path):
            continue
        elif SENSITIVE_KEY_RE.search(path):
            text = value if isinstance(value, str) else str(value)
            if text.strip() and text.strip().lower() not in ("null", "none"):
                out.append(path)
    return out


def header_issues(header: dict) -> list[tuple[str, str]]:
    """(description, cwe) hits for token-controlled key material and kid
    injection patterns. Pure — unit-tested directly."""
    issues: list[tuple[str, str]] = []
    for name in ("jwk", "jku", "x5u", "x5c"):
        if name in header:
            text, cwe = KEY_CONTROL_HEADERS[name]
            issues.append((f"{name}: {text}", cwe))
    kid = str(header.get("kid", "") or "")
    if kid:
        if KID_TRAVERSAL_RE.search(kid):
            issues.append(
                (f"kid: path traversal pattern in key id {kid!r} — if the "
                 "server opens kid as a file path, key lookup escapes the "
                 "key directory", "CWE-22"))
        if KID_SQL_RE.search(kid):
            issues.append(
                (f"kid: SQL metacharacter in key id {kid!r} — if the server "
                 "builds a lookup query from kid, the token injects SQL",
                 "CWE-89"))
        if KID_URL_RE.search(kid):
            issues.append(
                (f"kid: key id is a URL ({kid[:80]!r}) — remote/SSRF-style "
                 "key resolution surface", "CWE-347"))
    return issues


def jwt_verdict(header: dict, claims: dict, weak_secret: str | None,
                now: float | None = None) -> dict:
    """Pure decision function — unit-tested directly."""
    now = time.time() if now is None else now
    alg = str(header.get("alg", "")).upper()
    result: dict[str, Any] = {
        "alg": alg,
        "kid": str(header.get("kid", "")),
        "weak_secret": weak_secret or "",
        "sensitive_claims": [],
        "header_issues": [],
        "exp": claims.get("exp"),
        "iat": claims.get("iat"),
        "expired": False,
        "remaining_days": None,
        "cwe": "",
    }

    if weak_secret:
        result["verdict"] = "confirmed"
        result["cwe"] = "CWE-798"
        result["reason"] = (
            f"the HS* signature verifies with the well-known secret "
            f"{weak_secret!r} — anyone holding this token format can forge "
            "arbitrary tokens"
        )
        return result

    sensitive = _sensitive_claims(claims)
    result["sensitive_claims"] = sensitive[:20]
    if sensitive:
        result["verdict"] = "confirmed"
        result["cwe"] = "CWE-200"
        result["reason"] = (
            f"claims carry sensitive-named field(s) {sensitive[:20]} — JWT "
            "payloads are only base64-encoded, so anyone who sees the token "
            "(logs, URLs, referrers) can read them"
        )
        return result

    if alg == "NONE":
        result["verdict"] = "suspected"
        result["cwe"] = "CWE-347"
        result["reason"] = (
            "token is unsigned (alg \"none\") — if the server accepts it, "
            "forgery is trivial; server-side acceptance was NOT tested here"
        )
        return result

    issues = header_issues(header)
    result["header_issues"] = [text for text, _ in issues]
    if issues:
        result["verdict"] = "suspected"
        result["cwe"] = issues[0][1]
        result["reason"] = (
            "key-material/kid injection surface: "
            + "; ".join(text for text, _ in issues)
            + " — server-side acceptance NOT tested here"
        )
        return result

    exp = claims.get("exp")
    exp_ok = isinstance(exp, (int, float))
    if not exp_ok:
        result["verdict"] = "suspected"
        result["cwe"] = "CWE-613"
        result["reason"] = (
            "no exp claim — the token carries no enforced expiry; session "
            "lifetime is left to server config"
        )
        return result

    remaining = float(exp) - now
    result["remaining_days"] = round(remaining / 86400, 1)
    if remaining <= 0:
        result["expired"] = True
        result["verdict"] = "no_issue"
        result["reason"] = (
            f"token expired {abs(result['remaining_days'])} days ago — if "
            "the server still accepts it, that is a server-side finding "
            "testable with the session tools"
        )
        return result

    if remaining > LONG_LIVED_DAYS * 86400:
        result["verdict"] = "suspected"
        result["cwe"] = "CWE-613"
        result["reason"] = (
            f"token stays valid for {result['remaining_days']} more days "
            f"(> {LONG_LIVED_DAYS}) — long-lived sessions widen the theft "
            "window"
        )
        return result

    result["verdict"] = "no_issue"
    result["reason"] = (
        f"static checks passed: HS secret not guessable, no sensitive "
        f"claims, expires in {result['remaining_days']} days"
        + ("" if alg.startswith("HS") else
           f"; note: {alg or 'unknown'} signature not verifiable locally")
    )
    return result


class JwtCheckTool(Tool):
    name = "jwt_check"
    description = (
        "Static JWT analysis (no target traffic): decodes header/claims and "
        "checks (a) HS* signature against well-known secrets, (b) sensitive "
        "data in the base64-readable payload, (c) alg none, (d) expiry "
        "claims, (e) token-controlled key material and kid injection "
        "patterns (jwk/jku/x5u/x5c headers, traversal/SQL/URL in kid). "
        "Verdicts: confirmed | suspected | no_issue. IMPORTANT: "
        "'source' should say where you observed the token (e.g. 'login "
        "response body') — confirmed findings need that provenance for "
        "evidence standards. RS*/ES* signatures cannot be verified locally."
    )
    binary = None
    parameters = {
        "type": "object",
        "properties": {
            "token": {"type": "string",
                      "description": "The JWT to analyze (header.payload"
                                     ".signature)"},
            "source": {"type": "string",
                       "description": "Where the token was observed, e.g. "
                                      "'login response body' or 'session "
                                      "cookie' — required for confirmed "
                                      "findings"},
        },
        "required": ["token"],
    }

    def run(self, args: dict[str, Any]) -> ToolResult:
        token = str(args.get("token", "") or "")
        source = str(args.get("source", "") or "").strip()
        if not token:
            raise ToolError("token is required")

        header, claims, signature = parse_jwt(token)
        alg = str(header.get("alg", ""))
        tok = token.strip()
        if tok.lower().startswith("bearer "):
            tok = tok[7:].strip()
        parts = tok.split(".")
        signing_input = f"{parts[0]}.{parts[1]}"
        weak = verify_weak_secret(signing_input, signature, alg)

        v = jwt_verdict(header, claims, weak)

        provenance = (f"token observed in response: {source}" if source
                      else "provenance: NOT provided by caller")
        evidence = (
            f"jwt_check evidence: {provenance}\n"
            f"alg={v['alg']} kid={v['kid'] or '(none)'} "
            f"weak_secret_verified={v['weak_secret'] or False} "
            f"expired={v['expired']} remaining_days={v['remaining_days']}\n"
            f"header_issues={v['header_issues']}\n"
            f"header={json.dumps(header, sort_keys=True)[:400]}\n"
            f"claims={json.dumps(claims, sort_keys=True)[:700]}\n"
            f"signature segment: omitted from record "
            f"(length {len(signature)})"
        )
        evidence = redactor.scrub(evidence)

        recommendation = {
            "confirmed": f"record_finding with status 'confirmed' "
                         f"({v['cwe']}) using this evidence",
            "suspected": f"record_finding with status 'suspected' + caveat "
                         f"({v['cwe']}) — server-side acceptance not tested",
            "no_issue": "do NOT record a finding — note the checked item "
                        "in coverage",
        }[v["verdict"]]

        return ToolResult(
            ok=True,
            summary=f"jwt_check verdict: {v['verdict']} — {v['reason']}",
            data={**v, "source": source, "evidence": evidence,
                  "recommendation": recommendation},
        )
