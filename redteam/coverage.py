"""Coverage matrix: maps the vulnerability catalog's 28 sections to what this
platform can actually test, and states honestly what it cannot.

This is the product answer to an impossible promise ("scan everything"):
every report says what was checked, how, and why the rest was not.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Collection

# tier meanings:
#   checked   — tested automatically on every run, unauthenticated, external
#   partial   — some sub-classes tested; the rest need access this run lacks
#   gated     — testable only with credentials/session (operator-supplied)
#   external  — needs infrastructure access (cloud, cluster, repo, device)
#   human     — organizational/process area, not scannable
#   excluded  — deliberately never automated (destructive or physical risk)


@dataclass(frozen=True)
class CoverageRow:
    section: str
    tier: str
    how: str  # which module, or the prerequisite that's missing


CATALOG: list[CoverageRow] = [
    CoverageRow("1. Web Application Vulnerabilities", "partial",
                "nuclei_scan (injection, XSS, ... templates) + web_security_checks; "
                "logic/race issues need an authenticated session (exploit stage)"),
    CoverageRow("2. Authentication and Session", "gated",
                "needs operator-supplied credentials; unauth checks only "
                "(cookie flags via web_security_checks)"),
    CoverageRow("3. Authorization and Access Control", "gated",
                "IDOR/BOLA need 2+ accounts to compare; not testable blind"),
    CoverageRow("4. API Security", "partial",
                "nuclei_scan API templates + web_security_checks; "
                "API key authz testing needs keys"),
    CoverageRow("5. Network Vulnerabilities", "checked",
                "nmap_scan (ports/services) + nuclei_scan service templates + tls_check"),
    CoverageRow("6. OS and Server", "partial",
                "service version detection only; patch/config state needs host access"),
    CoverageRow("7. Cloud Security", "external",
                "needs cloud IAM credentials (out of band scanners like ScoutSuite)"),
    CoverageRow("8. Database", "partial",
                "exposed DB ports via nmap_scan; config/roles need DB access"),
    CoverageRow("9. Cryptography and Data Protection", "checked",
                "tls_check (versions, cert validity/expiry) + nuclei TLS templates"),
    CoverageRow("10. File Handling and Uploads", "partial",
                "exposed backup/config files via web_security_checks; "
                "upload behavior needs an account and is gated"),
    CoverageRow("11. Business Logic and Workflow", "gated",
                "needs authenticated session + operator knowledge of the workflow"),
    CoverageRow("12. Configuration and Deployment", "checked",
                "web_security_checks (headers, CORS, cookies, exposed files, methods) "
                "+ nuclei tech templates + robots_recon custom check"),
    CoverageRow("13. Dependencies and Supply Chain", "external",
                "needs source manifests/SBOM or package registry access"),
    CoverageRow("14. Mobile Applications", "external", "needs APK/IPA artifact"),
    CoverageRow("15. Container and Kubernetes", "external",
                "needs cluster credentials; image scanning is a CI concern"),
    CoverageRow("16. Identity and Access Management", "external",
                "needs IdP/tenant admin access"),
    CoverageRow("17. Active Directory", "external",
                "needs domain credentials and AD-specific tooling (BloodHound etc.)"),
    CoverageRow("18. IoT and Embedded", "external", "needs device/firmware access"),
    CoverageRow("19. AI and LLM Security", "external",
                "needs an AI system in scope with its own test harness"),
    CoverageRow("20. Email and Human-Factor", "partial",
                "email_auth_check (SPF/DKIM/DMARC/MX, DNS only); "
                "phishing simulation is a human program"),
    CoverageRow("21. Forensics and Incident Response", "human",
                "audit/IR readiness is an organizational review, not a scan"),
    CoverageRow("22. Denial of Service", "excluded",
                "deliberately never automated: active DoS testing can disrupt real users"),
    CoverageRow("23. Privacy and Sensitive Data", "partial",
                "PII/secrets visible in unauthenticated responses (analyst review); "
                "retention/deletion are process questions"),
    CoverageRow("24. Source Code and Development", "partial",
                "exposed VCS metadata (.git/config, .hg, .bzr) via the exposed_vcs "
                "custom check; full SAST/secret scanning still needs repository "
                "access"),
    CoverageRow("25. Known CVEs and Intelligence", "checked",
                "nuclei_scan template/CVE matching + service version fingerprints; "
                "CWE/CVSS/CVE carried onto findings"),
    CoverageRow("26. Industrial Control (OT/ICS)", "excluded",
                "passive-only policy: active ICS testing can cause physical harm"),
    CoverageRow("27. Classification Standards", "checked",
                "findings carry CWE/CVSS/CVE from nuclei classifications; "
                "OWASP mapping in the report"),
    CoverageRow("28. MVP Roadmap", "human", "product process, not a vulnerability"),
]

TIER_BADGE = {
    "checked": "CHECKED",
    "partial": "PARTIAL",
    "gated": "NEEDS CREDS",
    "external": "OUT OF BAND",
    "human": "HUMAN REVIEW",
    "excluded": "NEVER AUTO",
}


def render_coverage(identities: bool = False,
                    tools_used: Collection[str] = ()) -> str:
    """Render the matrix. When operator identities are configured the
    authenticated sections (2, 3, 4, 11) are re-worded — and only upgraded
    (3 -> CHECKED) when THIS RUN actually exercised the authz tools, so the
    matrix never claims work that did not happen."""
    used = set(tools_used)

    def row_text(row: CoverageRow) -> CoverageRow:
        if not identities:
            return row
        section = row.section
        if section.startswith("3."):
            if {"idor_diff", "bfla_check"} & used:
                return replace(
                    row, tier="checked",
                    how="idor_diff (IDOR/BOLA, read-only replay) + bfla_check "
                        "(privilege boundary) under operator-supplied "
                        "identities; verified verdicts only (CWE-639/285)")
            return replace(row, how=row.how + " — identities ARE configured "
                                           "but no idor_diff/bfla_check ran "
                                           "this run")
        if section.startswith("2."):
            if {"jwt_check", "session_login", "account_enum",
                    "session_check"} & used:
                return replace(
                    row, tier="partial",
                    how="jwt_check (alg=none, weak HS secret, kid/key-control "
                        "patterns, expiry — static) + account_enum "
                        "(response-diff existence oracle) + session_check "
                        "(cookie flags, logout invalidation, fixation) + "
                        "session_login verification; interactive "
                        "password-reset/OTP stepping remains manual")
            return replace(row, how=row.how + " — identities ARE configured "
                                           "but not exercised this run")
        if section.startswith("4."):
            if {"schema_diff", "bfla_check", "idor_diff"} & used:
                return replace(
                    row, tier="partial",
                    how=row.how + "; authenticated: schema_diff (excessive "
                                 "data) + bfla_check (API authz boundary)")
            return replace(row, how=row.how + " — identities ARE configured "
                                           "but not exercised this run")
        if section.startswith("11."):
            if {"workflow_step", "race_burst"} & used:
                return replace(
                    row, tier="partial",
                    how="workflow_step (operator-gated stateful plans: "
                        "checkout/coupon/quota/refund — strict order, "
                        "per-request approval, recorded state machine) + "
                        "race_burst (<=5 concurrent writes for "
                        "double-spend/TOCTOU with a declared invariant); "
                        "domain-specific rules still need operator knowledge")
            if "session_login" in used:
                return replace(
                    row, how="authenticated session available; stateful "
                             "workflow tests remain operator-designed — "
                             "workflow tools available but not exercised "
                             "this run")
            return replace(row, how=row.how + " — identities ARE configured "
                                           "but not exercised this run")
        return row

    lines = [
        "## Coverage Matrix — what was checked, what was not, and why",
        "",
        "This assessment cannot verify every vulnerability class from the catalog.",
        "Honest coverage accounting per section:",
        "",
        "| Catalog section | Coverage | How tested / what's missing |",
        "|---|---|---|",
    ]
    for row in CATALOG:
        shown = row_text(row)
        lines.append(
            f"| {shown.section} | {TIER_BADGE[shown.tier]} | {shown.how} |"
        )
    lines.append("")
    lines.append(
        "*NEEDS CREDS = testable with an operator-supplied account. "
        "OUT OF BAND = needs infrastructure access outside a black-box scan. "
        "NEVER AUTO = deliberately excluded for safety.*"
    )
    lines.append("")
    return "\n".join(lines)
