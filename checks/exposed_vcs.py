"""Custom check: exposed version-control metadata.

Deep complement to web_security_checks (which probes /.git/HEAD): this finds
.git/config (leaks the remote URL, sometimes with embedded credentials) and
Mercurial/Bazaar metadata. GET-only, unauthenticated, read-only.
"""

import re

import requests

MANIFEST = {
    "id": "exposed_vcs",
    "title": "Exposed version-control metadata",
    "catalog_section": 24,
    "description": (
        "GET-probes deep VCS metadata the base config audit misses: "
        "/.git/config (leaks remote URL and possibly embedded credentials), "
        "/.hg/requires, /.bzr/README. Confirms real content signatures — a "
        "200 alone is not treated as proof."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "url": {"type": "string",
                    "description": "Origin base URL, e.g. https://example.com"},
        },
        "required": ["url"],
    },
    "severity_default": "high",
    "prereqs": ["in-scope web origin"],
    "requires_active": False,
}

# (path, content signatures, severity, why it matters)
PROBES = [
    ("/.git/config", ("[core]", "[remote]"), "high",
     "Git config exposed: full source history and remote URL are downloadable"),
    ("/.hg/requires", ("revlogv1", "requirements"), "medium",
     "Mercurial metadata exposed: source history may be downloadable"),
    ("/.bzr/README", ("bazaar", "branch"), "medium",
     "Bazaar branch metadata exposed: source history may be downloadable"),
]


def run(ctx):
    from redteam.http import ScopedHttpError

    base = str(ctx.args["url"]).rstrip("/")
    findings = []
    checked = []
    for path, signatures, severity, why in PROBES:
        url = base + path
        try:
            resp = ctx.session.get(url, timeout=8, allow_redirects=False)
        except (requests.RequestException, ScopedHttpError) as exc:
            checked.append({"path": path, "error": type(exc).__name__})
            continue
        checked.append({"path": path, "status": resp.status_code})
        body_head = resp.text[:4000]
        if resp.status_code == 200 and any(s.lower() in body_head.lower()
                                           for s in signatures):
            finding = {
                "severity": severity,
                "title": f"Exposed: {path}",
                "detail": why,
                "evidence": f"GET {path} -> {resp.status_code}; "
                             f"content matched {signatures[0]!r}",
                "url": url,
                "remediation": "Deny web access to VCS directories "
                               "(.git/.hg/.bzr) at the server or CDN.",
            }
            if path == "/.git/config":
                m = re.search(r"url\s*=\s*(\S+)", body_head)
                if m:
                    finding["remote_url"] = m.group(1)[:200]
            findings.append(finding)

    return {
        "summary": f"VCS metadata probe: {len(findings)} exposure(s) "
                   f"across {len(PROBES)} path(s)",
        "findings": findings,
        "checked": checked,
    }
