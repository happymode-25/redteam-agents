"""Repo/SCA scanners (Phase 3.1: catalog sections 13, 24, parts of 12/15).

Five offline binaries wrapped as tools with deterministic parsers. Safety
and honesty rules enforced in CODE, mirroring the web tooling:

- The scanned root is fixed at construction time; the tools expose NO path
  argument in their JSON schema, so the LLM can never redirect a scanner
  at anything the operator did not authorize. Repo path containment itself
  is enforced by redteam.repo.RepoScanner (allowlist + resolve()).
- Evidence carries the `scanner:` marker (added to the evidence standard in
  state.py): static findings prove a CODE defect, not a runtime one, and
  the verdict ladder says so —
    secret_scan   confirmed  — the hardcoded-credential defect is proven by
                               file:line. Matches arrive redacted by gitleaks
                               (--redact) and liveness is NEVER tested: the
                               credential is reported, never used.
    dep_scan      confirmed  — version-range matches are deterministic
                               (CVE/GHSA ids attached).
    iac_scan      confirmed  — the misconfiguration exists in code.
    sast_scan     suspected  — static patterns need runtime/dataflow proof;
                               the recommendation names what to run against a
                               living instance.
    sbom_build    no finding — inventory artifact only.
- semgrep runs with --metrics=off in code (source never leaves the machine),
  like nuclei's -duc. osv-scanner is the only scanner that can touch the
  network (package names+versions to the OSV API) and is gated by
  repo.osv_online (same third-party-disclosure philosophy as intel.enabled).
- Scanners that are missing from PATH degrade gracefully: available() is
  false, the agent is told up front, and the coverage matrix never claims
  the work (coverage.py keys off used_tools).
"""

from __future__ import annotations

import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any

from ..config import RepoConfig
from ..redact import redactor
from .base import Tool, ToolError, ToolResult

_GITLEAKS_TIMEOUT = 900
_SEMGREP_TIMEOUT = 1800
_OSV_TIMEOUT = 900
_CHECKOV_TIMEOUT = 1800
_SYFT_TIMEOUT = 900

_RAW_CAP = 200_000  # bytes of raw scanner stdout kept per tool result

# secret rules whose exposure is immediately critical
_CRITICAL_SECRET_RE = re.compile(
    r"private[-_ ]?key|aws|stripe|heroku|github[-_ ]?token|npm[-_ ]?token|"
    r"slack[-_ ]?token|secret[-_ ]?key|jwt[-_ ]?token|password",
    re.I,
)

_CVSS_NUMERIC_RE = re.compile(r"^(\d+(?:\.\d+)?)$")
_OSV_SEVERITY_MAP = {
    "CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium",
    "MODERATE": "medium", "LOW": "low", "INFO": "info",
}
_CHECKOV_SEVERITY_MAP = {
    "CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium",
    "LOW": "low", "INFO": "info",
}


def cvss_to_severity(score: float) -> str:
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0:
        return "low"
    return "info"


def _rel(root: Path, file: str) -> str:
    """Scanner paths (relative, root-relative-with-slash, or absolute)
    rendered repo-relative for findings."""
    p = Path(file)
    if not p.is_absolute():
        p = root / p          # resolve() alone would anchor to the CWD
    try:
        return str(p.resolve().relative_to(root)).replace("\\", "/")
    except (ValueError, OSError):
        return str(file).replace("\\", "/").lstrip("/") or str(file)


def secret_severity(rule_id: str, tags: list[str]) -> str:
    probe = f"{rule_id} {' '.join(tags)}"
    return "critical" if _CRITICAL_SECRET_RE.search(probe) else "high"


def osv_severity(vuln: dict) -> tuple[str, str]:
    """(severity, cvss_or_note) from one OSV vulnerability object.

    osv-scanner emits database_specific.severity (OSV DB label) and/or a
    CVSS vector string in severity[].score; a bare numeric is honored too.
    A bare CVSS vector is kept as evidence but NOT base-score-computed
    (that would be guesswork; the label decides).
    """
    label = str((vuln.get("database_specific") or {}).get("severity") or "")
    if label.upper() in _OSV_SEVERITY_MAP:
        return _OSV_SEVERITY_MAP[label.upper()], ""
    for entry in vuln.get("severity") or []:
        score = str(entry.get("score") or "")
        numeric = _CVSS_NUMERIC_RE.match(score.strip())
        if numeric:
            return cvss_to_severity(float(numeric.group(1))), score[:80]
        if score:
            return "medium", score[:80]   # vector without computed base score
    return "medium", ""


def parse_gitleaks(text: str, root: Path) -> list[dict]:
    try:
        raw = json.loads(text)
    except ValueError as exc:
        raise ToolError(f"gitleaks output is not JSON: {exc}") from exc
    if not isinstance(raw, list):
        raise ToolError(f"unexpected gitleaks JSON shape: {type(raw).__name__}")
    out: list[dict] = []
    for hit in raw:
        rule = str(hit.get("RuleID") or hit.get("Rule") or "unknown-rule")
        tags = [str(t) for t in (hit.get("Tags") or [])]
        file = _rel(root, str(hit.get("File") or "?"))
        line = int(hit.get("StartLine") or 0)
        sev = secret_severity(rule, tags)
        out.append({
            "rule": rule,
            "file": file,
            "line": line,
            "severity": sev,
            "description": str(hit.get("Description") or "")[:300],
            # the scanner redacts with --redact; we never receive a value
            "match": "***redacted***",
            "entropy": hit.get("Entropy"),
            "record": {
                "title": f"Hardcoded credential: {rule} in {file}",
                "severity": sev,
                "status": "confirmed",
                "cwe": "CWE-798",
                "target": f"{file}:{line}",
                "evidence": redactor.scrub(
                    f"scanner: gitleaks rule {rule} matched at {file}:{line} "
                    f"({hit.get('Description') or 'credential'}; the match is "
                    "redacted by the scanner itself — no secret value was seen "
                    "or stored). LIVENESS NOT TESTED: the credential was "
                    "reported, never used."
                ),
                "remediation": (
                    "Rotate the exposed credential, purge it from history, and "
                    "load secrets from an env var or secret manager. Verify "
                    "manually whether the value is still live."
                ),
            },
        })
    return out


def parse_semgrep(text: str, root: Path) -> list[dict]:
    try:
        data = json.loads(text)
    except ValueError as exc:
        raise ToolError(f"semgrep output is not JSON: {exc}") from exc
    results = data.get("results") if isinstance(data, dict) else None
    if not isinstance(results, list):
        raise ToolError("unexpected semgrep JSON shape (no 'results' list)")
    sev_map = {"ERROR": "high", "WARNING": "medium", "INFO": "info"}
    out: list[dict] = []
    for hit in results:
        extra = hit.get("extra") or {}
        raw_sev = str(extra.get("severity") or "INFO").upper()
        severity = sev_map.get(raw_sev, "info")
        meta = extra.get("metadata") or {}
        cwe_raw = meta.get("cwe") or []
        if isinstance(cwe_raw, str):
            cwe_raw = [cwe_raw]
        cwe = ""
        if cwe_raw:
            cwe = str(cwe_raw[0]).split(":")[0].strip()  # "CWE-89: ..." -> CWE-89
        rule = str(hit.get("check_id") or "unknown-rule")
        file = _rel(root, str(hit.get("path") or "?"))
        line = int((hit.get("start") or {}).get("line") or 0)
        code = str(extra.get("lines") or "").strip()[:400]
        out.append({
            "rule": rule,
            "file": file,
            "line": line,
            "severity": severity,
            "semgrep_severity": raw_sev,
            "cwe": cwe,
            "message": str(extra.get("message") or "")[:300],
            "confidence": str(meta.get("confidence") or "")[:20],
            "record": {
                "title": f"SAST: {rule} in {file}",
                "severity": severity,
                "status": "suspected",   # static pattern — no runtime proof
                "cwe": cwe,
                "cvss": "",
                "target": f"{file}:{line}",
                "evidence": redactor.scrub(
                    f"scanner: semgrep rule {rule} [{raw_sev}] at {file}:{line}"
                    f" — {extra.get('message') or ''}\n  code: {code}\n"
                    "Static pattern only: no runtime traffic proves exploitability."
                ),
                "remediation": (
                    "Confirm against a running instance (authorized request "
                    "that exercises this code path) or review the dataflow "
                    "manually; then fix the sink/sanitization."
                ),
            },
        })
    return out


def parse_osv(text: str, root: Path) -> list[dict]:
    try:
        data = json.loads(text)
    except ValueError as exc:
        raise ToolError(f"osv-scanner output is not JSON: {exc}") from exc
    results = data.get("results") if isinstance(data, dict) else None
    if not isinstance(results, list):
        raise ToolError("unexpected osv-scanner JSON shape (no 'results' list)")
    out: list[dict] = []
    for source in results:
        source_path = _rel(root, str((source.get("source") or {}).get("path") or "?"))
        for pkg in source.get("packages") or []:
            info = pkg.get("package") or {}
            name = str(info.get("name") or "?")
            version = str(info.get("version") or "?")
            for vuln in pkg.get("vulnerabilities") or []:
                severity, cvss = osv_severity(vuln)
                ids = [str(vuln.get("id") or "")]
                ids += [str(a) for a in vuln.get("aliases") or []]
                ids = [i for i in dict.fromkeys(ids) if i]
                cves = ",".join(i for i in ids if i.startswith("CVE-"))
                out.append({
                    "package": name,
                    "version": version,
                    "source": source_path,
                    "ids": ids,
                    "severity": severity,
                    "summary": str(vuln.get("summary") or "")[:300],
                    "record": {
                        "title": f"Vulnerable dependency: {name}=={version} ({ids[0] if ids else 'unknown-id'})",
                        "severity": severity,
                        "status": "confirmed",   # version-range match is deterministic
                        "cwe": "",
                        "cvss": cvss,
                        "cves": cves,
                        "target": f"{source_path} ({name}=={version})",
                        "evidence": redactor.scrub(
                            f"scanner: osv-scanner matched {', '.join(ids[:4])} "
                            f"for {name}=={version} in {source_path} — the pinned "
                            "version falls inside the advisory's vulnerable "
                            f"range.{(' cvss: ' + cvss) if cvss else ''}"
                        ),
                        "remediation": (
                            f"Upgrade {name} to the first non-vulnerable release "
                            "named in the advisory (or remove it), then re-run "
                            "dep_scan to confirm."
                        ),
                    },
                })
    return out


def parse_checkov(text: str, root: Path) -> list[dict]:
    try:
        data = json.loads(text)
    except ValueError as exc:
        raise ToolError(f"checkov output is not JSON: {exc}") from exc
    results = (data.get("results") or {}) if isinstance(data, dict) else {}
    failed = results.get("failed_checks")
    if failed is None:
        raise ToolError("unexpected checkov JSON shape (no failed_checks)")
    out: list[dict] = []
    for hit in failed:
        raw_sev = str(hit.get("severity") or "").upper()
        severity = _CHECKOV_SEVERITY_MAP.get(raw_sev, "medium")
        check = str(hit.get("check_id") or "CKV-UNKNOWN")
        file = _rel(root, str(hit.get("file_path") or "?"))
        line = int(hit.get("line_number") or 0)
        resource = str(hit.get("resource") or "?")
        out.append({
            "check_id": check,
            "file": file,
            "line": line,
            "severity": severity,
            "resource": resource,
            "check_name": str(hit.get("check_name") or "")[:300],
            "record": {
                "title": f"IaC misconfiguration: {check} in {file}",
                "severity": severity,
                "status": "confirmed",   # the misconfig exists in code
                "cwe": "",
                "target": f"{file}:{line} ({resource})",
                "evidence": redactor.scrub(
                    f"scanner: checkov {check} FAILED for {resource} at "
                    f"{file}:{line} — {hit.get('check_name') or ''}"
                ),
                "remediation": str(hit.get("guideline") or
                                   "Fix the resource configuration per the check.")[:400],
            },
        })
    return out


class _RepoTool(Tool):
    """Shared construction: a FIXED resolved root (never an LLM argument)
    plus the repo policy config. Scanners exclude the configured noisy
    directories; nothing else is filtered."""

    def __init__(self, root: Path, cfg: RepoConfig):
        self.root = Path(root)
        self.cfg = cfg


class SecretScanTool(_RepoTool):
    name = "secret_scan"
    description = (
        "Hardcoded-secret scan of the repository with gitleaks. Matches are "
        "redacted BY THE SCANNER (--redact is forced in code): no secret "
        "value reaches the operator, the report, or the model. Findings are "
        "status 'confirmed' (the hardcoded-credential defect is proven by "
        "file:line) but liveness is never tested — credentials are reported, "
        "never used. No arguments."
    )
    binary = "gitleaks"
    parameters = {"type": "object", "properties": {}}

    def run(self, args: dict[str, Any]) -> ToolResult:
        # report goes to a temp FILE, not stdout: `--report-path -` support
        # differs across gitleaks versions and a silent empty stdout on a
        # real leak would be the worst possible failure mode.
        import tempfile
        tmp = tempfile.NamedTemporaryFile(suffix=".json", delete=False)
        tmp.close()
        report_path = Path(tmp.name)
        try:
            cmd = ["gitleaks", "dir", str(self.root), "--report-format", "json",
                   "--report-path", str(report_path), "--no-banner",
                   "--exit-code", "0", "--redact"]
            for ex in self.cfg.exclude:
                cmd += ["--exclude-path", f".*{re.escape(ex)}.*"]
            proc = self.shell(cmd, timeout=_GITLEAKS_TIMEOUT)
            try:
                stdout = report_path.read_text(encoding="utf-8",
                                               errors="replace").strip()
            except OSError:
                stdout = ""
        finally:
            report_path.unlink(missing_ok=True)
        if not stdout or stdout == "[]":
            if proc.returncode != 0 and not stdout:
                raise ToolError(f"gitleaks failed (rc={proc.returncode}): "
                                f"{(proc.stderr or '')[:300]}")
            return ToolResult(ok=True, summary="gitleaks found no hardcoded secrets")
        findings = parse_gitleaks(stdout, self.root)
        return ToolResult(
            ok=True,
            summary=(f"secret_scan: {len(findings)} hardcoded credential(s); "
                     "matches redacted by the scanner, liveness not tested"),
            data={"count": len(findings), "findings": findings,
                  "note": "matches arrive redacted (--redact); the scanner "
                          "never exposes the value to us"},
            raw=stdout[:_RAW_CAP],
        )


class SastScanTool(_RepoTool):
    name = "sast_scan"
    description = (
        "Static analysis with semgrep (--metrics=off forced in code — source "
        "never leaves this machine). Findings are 'suspected' only: a static "
        "pattern is not runtime proof; the recommendation names what to run "
        "against a living instance. No arguments."
    )
    binary = "semgrep"
    parameters = {"type": "object", "properties": {}}

    def run(self, args: dict[str, Any]) -> ToolResult:
        cmd = ["semgrep", "scan", "--json", "--metrics=off", "--quiet"]
        for ex in self.cfg.exclude:
            cmd.append(f"--exclude={ex}")
        cmd.append(str(self.root))
        proc = self.shell(cmd, timeout=_SEMGREP_TIMEOUT)
        stdout = (proc.stdout or "").strip()
        if not stdout:
            if proc.returncode != 0:
                raise ToolError(f"semgrep failed (rc={proc.returncode}): "
                                f"{(proc.stderr or '')[:300]}")
            return ToolResult(ok=True,
                              summary="sast_scan: no semgrep findings")
        findings = parse_semgrep(stdout, self.root)
        return ToolResult(
            ok=True,
            summary=(f"sast_scan: {len(findings)} static finding(s) — all "
                     "'suspected' pending runtime confirmation; metrics off"),
            data={"count": len(findings), "findings": findings,
                  "note": "metrics=off: no source code was sent anywhere"},
            raw=stdout[:_RAW_CAP],
        )


class DepScanTool(_RepoTool):
    name = "dep_scan"
    description = (
        "Vulnerable-dependency scan with osv-scanner over manifests/lockfiles "
        "(recursive). Version-range matches are deterministic -> 'confirmed' "
        "with CVE/GHSA ids. This is the ONE scanner that may touch the "
        "network (package names+versions to the OSV API) unless the operator "
        "set repo.osv_online: false. No arguments."
    )
    binary = "osv-scanner"
    parameters = {"type": "object", "properties": {}}

    def run(self, args: dict[str, Any]) -> ToolResult:
        cmd = ["osv-scanner", "scan", "source", str(self.root),
               "--format", "json", "--recursive"]
        if not self.cfg.osv_online:
            cmd.append("--offline")
        proc = self.shell(cmd, timeout=_OSV_TIMEOUT)
        # osv-scanner exits 1 when vulnerabilities are found
        stdout = (proc.stdout or "").strip()
        if not stdout:
            if proc.returncode not in (0, 1):
                raise ToolError(f"osv-scanner failed (rc={proc.returncode}): "
                                f"{(proc.stderr or '')[:300]}")
            return ToolResult(
                ok=True, summary="dep_scan: no known-vulnerable dependencies"
                                 + ("" if self.cfg.osv_online else " (offline DB)"))
        findings = parse_osv(stdout, self.root)
        return ToolResult(
            ok=True,
            summary=(f"dep_scan: {len(findings)} vulnerable dependency "
                     f"match(es)"
                     + ("" if self.cfg.osv_online else " (offline local DB)")),
            data={"count": len(findings), "findings": findings,
                  "network": ("OSV API (package names only)" if self.cfg.osv_online
                              else "offline — local OSV database")},
            raw=stdout[:_RAW_CAP],
        )


class IacScanTool(_RepoTool):
    name = "iac_scan"
    description = (
        "Infrastructure-as-code misconfiguration scan with checkov over the "
        "repository (Terraform/CloudFormation/ARM/K8s/Dockerfile...). The "
        "misconfiguration exists in code -> 'confirmed'. No external module "
        "download (checkov's default) and no arguments."
    )
    binary = "checkov"
    parameters = {"type": "object", "properties": {}}

    def run(self, args: dict[str, Any]) -> ToolResult:
        cmd = ["checkov", "-d", str(self.root), "--output", "json", "--quiet"]
        for ex in self.cfg.exclude:
            cmd += ["--exclude-dir", ex]
        proc = self.shell(cmd, timeout=_CHECKOV_TIMEOUT)
        stdout = (proc.stdout or "").strip()
        if not stdout:
            if proc.returncode != 0:
                raise ToolError(f"checkov failed (rc={proc.returncode}): "
                                f"{(proc.stderr or '')[:300]}")
            return ToolResult(ok=True, summary="iac_scan: no failed checks")
        findings = parse_checkov(stdout, self.root)
        return ToolResult(
            ok=True,
            summary=f"iac_scan: {len(findings)} failed check(s)",
            data={"count": len(findings), "findings": findings},
            raw=stdout[:_RAW_CAP],
        )


class SbomBuildTool(_RepoTool):
    name = "sbom_build"
    description = (
        "Build a CycloneDX SBOM of the repository with syft; the JSON lands "
        "in the artifacts directory and the result summarizes component "
        "counts by package type. Inventory only — produces no finding and "
        "no network traffic. No arguments."
    )
    binary = "syft"
    parameters = {"type": "object", "properties": {}}

    def __init__(self, root: Path, cfg: RepoConfig, artifacts: Path):
        super().__init__(root, cfg)
        self.artifacts = Path(artifacts)

    def run(self, args: dict[str, Any]) -> ToolResult:
        proc = self.shell(["syft", f"dir:{self.root}", "-o", "json"],
                          timeout=_SYFT_TIMEOUT)
        stdout = (proc.stdout or "").strip()
        if not stdout:
            raise ToolError(f"syft failed (rc={proc.returncode}): "
                            f"{(proc.stderr or '')[:300]}")
        try:
            data = json.loads(stdout)
        except ValueError as exc:
            raise ToolError(f"syft output is not JSON: {exc}") from exc
        artifacts_list = data.get("artifacts") or []
        by_type: dict[str, int] = {}
        for comp in artifacts_list:
            kind = str(comp.get("type") or "unknown")
            by_type[kind] = by_type.get(kind, 0) + 1
        out = self.artifacts / f"sbom-{datetime.now().strftime('%Y%m%d-%H%M%S')}.json"
        out.write_text(redactor.scrub(stdout[:2_000_000]), encoding="utf-8")
        top = sorted(by_type.items(), key=lambda kv: -kv[1])[:5]
        return ToolResult(
            ok=True,
            summary=(f"sbom_build: {len(artifacts_list)} component(s); top "
                     f"types: {', '.join(f'{k}={v}' for k, v in top) or 'none'}"),
            data={"component_count": len(artifacts_list),
                  "by_type": dict(sorted(by_type.items())),
                  "artifact": str(out)},
            raw="",
        )
