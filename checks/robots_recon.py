"""Custom check: robots.txt reconnaissance analysis.

Parses /robots.txt and flags disclosed paths that look sensitive (admin,
backups, staging, .git, internal tooling). Disclosure itself is the finding —
the check never requests the disclosed paths. GET-only, unauthenticated.
"""

MANIFEST = {
    "id": "robots_recon",
    "title": "robots.txt sensitive path disclosure",
    "catalog_section": 12,
    "description": (
        "Fetches /robots.txt, parses Disallow/Allow entries and flags paths "
        "that disclose sensitive areas (admin, backups, staging, .git, "
        "internal tooling). Read-only analysis: disclosed paths are reported, "
        "never requested."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "url": {"type": "string",
                    "description": "Origin base URL, e.g. https://example.com"},
        },
        "required": ["url"],
    },
    "severity_default": "low",
    "prereqs": ["in-scope web origin"],
    "requires_active": False,
}

SENSITIVE_KEYWORDS = (
    "admin", "backup", ".git", "staging", "internal", "private",
    "tmp", "temp", "dev", "test", "config", "console", "manager",
    "upload", "old", "dump", "cron", "debug", ".env", "db", "secret",
)
MAX_REPORTED = 20


def run(ctx):
    from redteam.http import ScopedHttpError

    import requests

    base = str(ctx.args["url"]).rstrip("/")
    url = base + "/robots.txt"
    try:
        resp = ctx.session.get(url, timeout=8, allow_redirects=True)
    except (requests.RequestException, ScopedHttpError) as exc:
        return {"summary": f"robots.txt unreachable ({type(exc).__name__})",
                "findings": [], "status": None}

    if resp.status_code != 200:
        return {"summary": f"robots.txt absent (HTTP {resp.status_code}) — "
                           "nothing to analyze",
                "findings": [], "status": resp.status_code}

    paths: list[str] = []
    for line in resp.text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        for directive in ("Disallow:", "Allow:"):
            if line.startswith(directive):
                value = line[len(directive):].strip()
                if value and value not in paths:
                    paths.append(value)
                break

    sensitive = [p for p in paths
                 if any(k in p.lower() for k in SENSITIVE_KEYWORDS)]

    findings = [
        {
            "severity": "low",
            "title": f"Sensitive path disclosed in robots.txt: {p}",
            "detail": "robots.txt announces a path that looks like sensitive "
                      "or non-public functionality — disclosure aids targeted "
                      "reconnaissance.",
            "evidence": f"GET /robots.txt (HTTP 200), entry: {p}",
            "url": url,
            "remediation": "Remove sensitive paths from robots.txt; enforce "
                           "access control — robots.txt is not protection.",
        }
        for p in sensitive[:MAX_REPORTED]
    ]

    return {
        "summary": f"robots.txt: {len(paths)} path(s) declared, "
                   f"{len(sensitive)} look sensitive",
        "findings": findings,
        "status": resp.status_code,
        "disallowed": paths[:50],
        "sensitive": sensitive[:MAX_REPORTED],
    }
