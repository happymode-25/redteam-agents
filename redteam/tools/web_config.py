"""Web configuration checks (section 12/1/9/23 coverage).

Pure Python (requests only) — no external binaries. Passive: a handful of
GET/HEAD/OPTIONS requests against one authorized URL. Detects security
header gaps, insecure cookies, CORS misconfiguration, exposed sensitive
files, directory listing, and dangerous HTTP methods.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urljoin

import requests

from ..http import ScopedHttpError, ScopedSession
from ..scope import Guard
from .base import Tool, ToolError, ToolResult

REQUIRED_HEADERS = {
    "Strict-Transport-Security": "HSTS missing: no HTTPS upgrade enforcement",
    "Content-Security-Policy": "CSP missing: no XSS mitigation policy",
    "X-Content-Type-Options": "X-Content-Type-Options missing: MIME sniffing risk",
    "X-Frame-Options": "X-Frame-Options missing: clickjacking risk "
                       "(or use CSP frame-ancestors)",
    "Referrer-Policy": "Referrer-Policy missing: URL leakage via Referer",
}

# (path, why it matters) — only 200 responses are reported as exposed
SENSITIVE_PATHS = {
    "/.git/HEAD": "Git repository exposed",
    "/.env": "Environment file exposed (secret leak risk)",
    "/.svn/entries": "SVN metadata exposed",
    "/.DS_Store": "Directory metadata exposed",
    "/.aws/credentials": "AWS credentials file exposed",
    "/server-status": "Server status page exposed",
    "/actuator/health": "Spring Actuator endpoint exposed",
    "/phpinfo.php": "phpinfo() exposure",
    "/backup.zip": "Backup archive exposed",
    "/config.php.bak": "Backup source file exposed",
}

PROBE_ORIGIN = "https://redteam-probe.invalid"


class WebSecurityChecksTool(Tool):
    name = "web_security_checks"
    description = (
        "Passive configuration audit of one authorized web URL: security headers, "
        "cookie flags, CORS policy, exposed sensitive files (.git, .env, backups), "
        "directory listing and dangerous HTTP methods. Sends only a handful of "
        "GET/HEAD/OPTIONS requests — no fuzzing, no exploitation."
    )
    parameters = {
        "type": "object",
        "properties": {
            "url": {"type": "string", "description": "Full URL to audit (must be in scope)"},
        },
        "required": ["url"],
    }

    def __init__(self, guard: Guard):
        self.guard = guard

    def run(self, args: dict[str, Any]) -> ToolResult:
        url = str(args["url"]).strip()
        session = ScopedSession(self.guard, timeout=15)

        try:
            resp = session.get(url, timeout=15, allow_redirects=True)
        except (requests.RequestException, ScopedHttpError) as exc:
            raise ToolError(f"could not fetch {url}: {exc}") from exc

        issues: list[str] = []
        data: dict[str, Any] = {"url": url, "status_code": resp.status_code}

        # --- security headers -------------------------------------------------
        header_gaps = []
        present = {k.lower(): v for k, v in resp.headers.items()}
        for header, why in REQUIRED_HEADERS.items():
            if header.lower() not in present:
                header_gaps.append(why)
        if "content-security-policy" in present and "frame-ancestors" not in present.get(
            "content-security-policy", ""
        ) and "x-frame-options" not in present:
            header_gaps.append("CSP lacks frame-ancestors and no X-Frame-Options: clickjacking risk")
        data["header_gaps"] = header_gaps
        issues += header_gaps

        disclosure = {
            k: present[k] for k in ("server", "x-powered-by", "x-aspnet-version")
            if k in present
        }
        data["version_disclosure"] = disclosure
        if disclosure:
            issues.append(f"technology disclosure headers present: {list(disclosure)}")

        # --- cookie flags -------------------------------------------------------
        cookie_issues = []
        for c in resp.cookies:
            if url.startswith("https") and not c.secure:
                cookie_issues.append(f"cookie '{c.name}' lacks Secure flag")
        set_cookie_headers = resp.headers.get("Set-Cookie", "")
        if set_cookie_headers:
            lowered = set_cookie_headers.lower()
            if url.startswith("https") and "secure" not in lowered:
                cookie_issues.append("Set-Cookie lacks Secure flag")
            if "httponly" not in lowered:
                cookie_issues.append("Set-Cookie lacks HttpOnly flag")
            if "samesite" not in lowered:
                cookie_issues.append("Set-Cookie lacks SameSite attribute (CSRF exposure)")
        data["cookie_issues"] = cookie_issues
        issues += cookie_issues

        # --- CORS ---------------------------------------------------------------
        try:
            cors_resp = session.get(
                url, headers={"Origin": PROBE_ORIGIN}, timeout=15, allow_redirects=True
            )
            acao = cors_resp.headers.get("Access-Control-Allow-Origin", "")
            acac = cors_resp.headers.get("Access-Control-Allow-Credentials", "").lower()
            cors = {
                "access_control_allow_origin": acao,
                "access_control_allow_credentials": acac,
            }
            if acao == PROBE_ORIGIN:
                issues.append(
                    "CORS reflects arbitrary Origin"
                    + (" WITH credentials: cross-origin data theft risk" if acac == "true" else "")
                )
            elif acao == "*":
                issues.append("CORS allows any origin (*)")
        except (requests.RequestException, ScopedHttpError):
            cors = {"error": "CORS probe failed"}
        data["cors"] = cors

        # --- dangerous methods --------------------------------------------------
        try:
            options = session.request("OPTIONS", url, timeout=15)
            allow = options.headers.get("Allow", "") or options.headers.get(
                "Access-Control-Allow-Methods", ""
            )
            dangerous = [m for m in ("PUT", "DELETE", "TRACE", "PATCH") if m in allow.upper()]
        except (requests.RequestException, ScopedHttpError):
            allow, dangerous = "", []
        data["allowed_methods"] = allow
        if dangerous:
            issues.append(f"dangerous HTTP methods advertised: {dangerous}")
        if "TRACE" in allow.upper():
            issues.append("TRACE enabled: XST risk")

        # --- directory listing ---------------------------------------------------
        if "index of /" in resp.text[:4096].lower():
            issues.append("Directory listing enabled on index page")
            data["directory_listing"] = True

        # --- exposed sensitive paths ---------------------------------------------
        exposed = []
        for path, why in SENSITIVE_PATHS.items():
            target = urljoin(resp.url + "/", path.lstrip("/"))
            try:
                r = session.get(target, timeout=10, allow_redirects=False)
            except (requests.RequestException, ScopedHttpError):
                continue
            if r.status_code == 200 and len(r.content) > 0:
                exposed.append({"path": path, "finding": why, "size": len(r.content)})
                issues.append(f"{why} at {path} (HTTP 200)")
        data["exposed_paths"] = exposed

        summary = f"{len(issues)} configuration issue(s) found at {url}"
        if not issues:
            summary = f"No configuration issues found at {url}"
        return ToolResult(ok=True, summary=summary, data=data)
