"""Container/Kubernetes scanners (catalog section 15).

Three read-only binaries wrapped as tools with deterministic parsers.
Safety and honesty rules enforced in CODE, mirroring tools/sca.py:

- The scan target is FIXED at construction time (image name, manifest
  directory, kubeconfig path); the tools expose NO argument in their JSON
  schema, so the LLM can never redirect a scanner or aim kubeaudit at a
  cluster the operator did not authorize.
- READ-ONLY everywhere: image_scan and kube_lint never touch a cluster at
  all (binary analysis of an image and of manifest files on disk), and
  kube_audit runs kubeaudit's audited READ-ONLY checks only — no kubectl
  apply/delete, no image push, no mutation anywhere in this module.
- Evidence carries the `scanner:` marker (state.py evidence standard).
  All three verdicts are deterministic observations of current state ->
  'confirmed' on the verdict ladder:
    image_scan  confirmed  — trivy matched an installed package version
                             inside the advisory's vulnerable range (the
                             CVE id is attached; no CVSS is invented — the
                             upstream severity label maps directly and
                             UNKNOWN defaults to medium).
    kube_lint   confirmed  — the manifest defect exists in code.
    kube_audit  confirmed  — the read-only audit observed the CURRENT
                             cluster state (Criticality -> severity;
                             missing criticality defaults to low).
- trivy may fetch its vulnerability DB and pull the scanned image on the
  operator's machine per its own defaults; nothing is ever pushed and no
  cluster object is touched.
- Scanners missing from PATH degrade gracefully: available() is false and
  the coverage matrix never claims the work.
"""

from __future__ import annotations

import json
from typing import Any

from ..redact import redactor
from .base import Tool, ToolError, ToolResult

_TRIVY_TIMEOUT = 1800
_KUBE_LINTER_TIMEOUT = 1800
_KUBEAUDIT_TIMEOUT = 1800

_RAW_CAP = 200_000  # bytes of raw scanner stdout kept per tool result

_TRIVY_SEVERITY_MAP = {
    "CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium",
    "LOW": "low", "UNKNOWN": "medium",   # unlabeled bucket: assume nothing better
}
_LINTER_SEVERITY_MAP = {
    "CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium",
    "LOW": "low", "INFO": "info",
}
_KUBEAUDIT_CRITICALITY_MAP = {"High": "high", "Medium": "medium"}


def _cap(text: str, n: int) -> str:
    """Truncate long scanner prose (remediations, titles) for evidence."""
    text = str(text or "")
    return text if len(text) <= n else text[:n] + "..."


def trivy_severity(label: str) -> str:
    """Upstream trivy label -> platform severity. UNKNOWN and anything
    unrecognized default to medium (never assume a vuln is harmless)."""
    return _TRIVY_SEVERITY_MAP.get(str(label or "").upper(), "medium")


def linter_severity(label: str) -> str:
    """Upstream kube-linter label -> platform severity."""
    return _LINTER_SEVERITY_MAP.get(str(label or "").upper(), "medium")


def kubeaudit_severity(criticality: str) -> str:
    """kubeaudit Criticality -> platform severity; missing -> low."""
    return _KUBEAUDIT_CRITICALITY_MAP.get(str(criticality or "").strip(), "low")


def parse_trivy_image(text: str, image: str) -> list[dict]:
    """Trivy `image --format json` -> one finding dict per vulnerability.

    The version-range match is done by trivy against its advisory
    databases — deterministic, so each finding records status
    'confirmed'. The upstream CVE id and severity label are carried
    through unchanged; no CVSS score is ever invented.
    """
    try:
        data = json.loads(text)
    except ValueError as exc:
        raise ToolError(f"trivy output is not JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise ToolError(f"unexpected trivy JSON shape: {type(data).__name__}")
    out: list[dict] = []
    for result in data.get("Results") or []:
        target = str(result.get("Target") or image)
        for vuln in result.get("Vulnerabilities") or []:
            cve = str(vuln.get("VulnerabilityID") or "unknown-cve")
            pkg = str(vuln.get("PkgName") or "unknown-package")
            installed = str(vuln.get("InstalledVersion") or "")
            fixed = str(vuln.get("FixedVersion") or "")
            label = str(vuln.get("Severity") or "UNKNOWN").upper()
            severity = trivy_severity(label)
            title = str(vuln.get("Title") or vuln.get("Description") or "")
            location = f"{pkg} {installed}".strip()
            out.append({
                "cve": cve,
                "package": pkg,
                "installed_version": installed,
                "fixed_version": fixed,
                "severity": severity,
                "scanner_severity": label,
                "target_layer": target,
                "record": {
                    "title": f"Vulnerable image package: {cve} in {pkg} ({image})",
                    "severity": severity,
                    "status": "confirmed",   # deterministic version-range match
                    "cwe": "",
                    "cves": cve,
                    "target": f"{image} :: {location} ({target})",
                    "evidence": redactor.scrub(
                        f"scanner: trivy matched {cve} ({label}) in {location} "
                        f"on {target}"
                        + (f" — {_cap(title, 200)}" if title else "")
                        + f"; fixed in {fixed or 'none — no fix available'}"
                    ),
                    "remediation": (
                        f"Upgrade {pkg} from {installed} to {fixed} and rebuild "
                        "the image, then re-run image_scan to confirm."
                        if fixed else
                        f"No fixed version is published for {location}: mitigate "
                        "via a WAF/virtual patch or remove the affected "
                        "component, then re-run image_scan to confirm."
                    ),
                },
            })
    return out


def parse_kube_linter(text: str) -> list[dict]:
    """kube-linter `run <dir> --format json` -> one finding per reported
    object. A report is a concrete manifest defect -> 'confirmed'."""
    try:
        data = json.loads(text)
    except ValueError as exc:
        raise ToolError(f"kube-linter output is not JSON: {exc}") from exc
    if not isinstance(data, dict) or "Reports" not in data:
        raise ToolError("unexpected kube-linter JSON shape (no 'Reports')")
    reports = data.get("Reports") or []
    if not isinstance(reports, list):
        raise ToolError("unexpected kube-linter JSON shape (Reports not a list)")
    out: list[dict] = []
    for report in reports:
        check = str(report.get("Check") or "unknown-check")
        label = str(report.get("Severity") or "MEDIUM").upper()
        severity = linter_severity(label)
        remediation = _cap(str(report.get("Remediation") or ""), 200)
        detail = remediation or "see the kube-linter check documentation"
        for entry in report.get("Objects") or [{}]:
            meta = (entry.get("Object") or {}).get("Metadata") or {}
            name = str(meta.get("Name") or "unknown-name")
            kind = str(meta.get("Kind") or "unknown-kind")
            file_info = entry.get("File") or {}
            path = str(file_info.get("Path") or "?")
            line = int(file_info.get("Line") or 0)
            out.append({
                "check": check,
                "severity": severity,
                "scanner_severity": label,
                "kind": kind,
                "name": name,
                "file": path,
                "line": line,
                "record": {
                    "title": f"Kubernetes manifest defect: {check} on {kind}/{name}",
                    "severity": severity,
                    "status": "confirmed",   # the defect exists in the manifest
                    "cwe": "",
                    "target": f"{kind}/{name} at {path}:{line}",
                    "evidence": redactor.scrub(
                        f"scanner: kube-linter {check} ({label}) on {kind}/{name}"
                        f" — remediation: {detail}"
                    ),
                    "remediation": (
                        remediation or "Fix the manifest per the kube-linter check."
                    ),
                },
            })
    return out


def parse_kubeaudit(text: str) -> list[dict]:
    """kubeaudit `all -o json` -> one finding per AuditResult.

    kubeaudit emits results only for PROBLEMS it observed through
    read-only API calls; observing the current cluster state makes each
    finding 'confirmed'.
    """
    try:
        data = json.loads(text)
    except ValueError as exc:
        raise ToolError(f"kubeaudit output is not JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise ToolError(f"unexpected kubeaudit JSON shape: {type(data).__name__}")
    out: list[dict] = []
    for result in data.get("Results") or []:
        name = str(result.get("AuditResultName") or "unknown-check")
        verbosity = str(result.get("Verbosity") or "").lower()
        criticality = str(result.get("Criticality") or "")
        severity = kubeaudit_severity(criticality)
        resource = str(result.get("ResourceName") or "unknown-resource")
        container = str(result.get("ContainerName") or "")
        namespace = str(result.get("Namespace") or "default")
        image = str(result.get("Image") or "")
        recommendation = _cap(str(result.get("Recommendation") or ""), 200)
        where = f"{namespace}/{resource}"
        if container:
            where += f" container={container}"
        out.append({
            "check": name,
            "severity": severity,
            "namespace": namespace,
            "resource": resource,
            "container": container,
            "image": image,
            "record": {
                "title": f"Kubernetes misconfiguration: {name} on {where}",
                "severity": severity,
                "status": "confirmed",   # current cluster state, read-only audit
                "cwe": "",
                "target": where,
                "evidence": redactor.scrub(
                    f"scanner: kubeaudit {name} ({verbosity or severity}) on "
                    f"{where}"
                    + (f" [image {image}]" if image else "")
                    + f" — {recommendation or 'see the kubeaudit check docs'}"
                ),
                "remediation": (
                    recommendation or "Apply the kubeaudit recommendation."
                ),
            },
        })
    return out


class ImageScanTool(Tool):
    """Offline container-image vulnerability scan with trivy.

    The image name is operator-configured and FIXED at construction: the
    schema exposes no arguments, so the LLM cannot redirect the scan.
    Read-only: trivy only reads the image (and may pull it plus its
    vulnerability DB on the operator's machine per its own defaults);
    no image is ever pushed. Version-range matches are 'confirmed' with
    the upstream CVE id and severity label.
    """
    name = "image_scan"
    description = (
        "Vulnerability scan of a FIXED operator-configured container image "
        "with trivy (vuln scanner only). Deterministic version-range "
        "matches -> status 'confirmed' with CVE ids; the upstream severity "
        "label maps directly (UNKNOWN -> medium) and no CVSS is invented. "
        "No arguments: the image is fixed at construction."
    )
    binary = "trivy"
    parameters = {"type": "object", "properties": {}}

    def __init__(self, image: str, timeout: int = _TRIVY_TIMEOUT):
        self.image = image
        self.timeout = timeout

    def run(self, args: dict[str, Any]) -> ToolResult:
        cmd = ["trivy", "image", "--format", "json", "--quiet",
               "--scanners", "vuln", self.image]
        proc = self.shell(cmd, timeout=self.timeout)
        stdout = (proc.stdout or "").strip()
        if not stdout:
            if proc.returncode != 0:
                raise ToolError(f"trivy failed (rc={proc.returncode}): "
                                f"{(proc.stderr or '')[:300]}")
            return ToolResult(ok=True, summary=(
                f"image_scan: no vulnerabilities reported for {self.image}"))
        findings = parse_trivy_image(stdout, self.image)
        if not findings:
            return ToolResult(
                ok=True,
                summary=f"image_scan: no known vulnerabilities in {self.image}",
                data={"count": 0, "image": self.image, "findings": []},
                raw=stdout[:_RAW_CAP],
            )
        samples = ", ".join(
            f"{f['cve']} ({f['scanner_severity']})" for f in findings[:3])
        return ToolResult(
            ok=True,
            summary=(f"image_scan: {len(findings)} vulnerability match(es) in "
                     f"{self.image}; e.g. {samples}"),
            data={"count": len(findings), "image": self.image,
                  "findings": findings},
            raw=stdout[:_RAW_CAP],
        )


class KubeLintTool(Tool):
    """Read-only manifest lint with kube-linter over an operator-placed
    directory of Kubernetes manifests. No cluster access at all: the
    scanner reads YAML files from disk. The directory is FIXED at
    construction — the schema exposes no arguments, so the LLM cannot
    redirect the scan. A report is a concrete manifest defect -> 'confirmed'.
    """
    name = "kube_lint"
    description = (
        "Static lint of a FIXED operator-provided directory of Kubernetes "
        "manifests with kube-linter (no cluster access). Each report is a "
        "concrete manifest defect -> status 'confirmed', with the upstream "
        "check id and remediation. No arguments: the directory is fixed at "
        "construction."
    )
    binary = "kube-linter"
    parameters = {"type": "object", "properties": {}}

    def __init__(self, lint_dir: str, timeout: int = _KUBE_LINTER_TIMEOUT):
        self.lint_dir = lint_dir
        self.timeout = timeout

    def run(self, args: dict[str, Any]) -> ToolResult:
        cmd = ["kube-linter", "run", self.lint_dir, "--format", "json"]
        proc = self.shell(cmd, timeout=self.timeout)
        stdout = (proc.stdout or "").strip()
        if not stdout:
            if proc.returncode != 0:
                raise ToolError(f"kube-linter failed (rc={proc.returncode}): "
                                f"{(proc.stderr or '')[:300]}")
            return ToolResult(ok=True,
                              summary="kube_lint: no kube-linter findings")
        findings = parse_kube_linter(stdout)
        if not findings:
            return ToolResult(ok=True,
                              summary="kube_lint: no kube-linter findings",
                              data={"count": 0, "findings": []},
                              raw=stdout[:_RAW_CAP])
        samples = ", ".join(f"{f['check']} ({f['scanner_severity']})"
                            for f in findings[:3])
        return ToolResult(
            ok=True,
            summary=(f"kube_lint: {len(findings)} manifest defect(s); "
                     f"e.g. {samples}"),
            data={"count": len(findings), "lint_dir": self.lint_dir,
                  "findings": findings},
            raw=stdout[:_RAW_CAP],
        )


class KubeAuditTool(Tool):
    """READ-ONLY cluster audit with kubeaudit.

    kubeaudit performs only its audited read-only checks (get/list of
    cluster resources); it performs NO mutation — no kubectl apply/delete,
    no image pushes, nothing writes to the cluster. The kubeconfig path
    and context are operator-supplied and FIXED at construction: the
    schema exposes no arguments, so the LLM cannot redirect the audit at
    another cluster or context. Observed current state -> 'confirmed'.
    """
    name = "kube_audit"
    description = (
        "READ-ONLY audit of a FIXED operator-authorized cluster (via an "
        "operator-supplied kubeconfig) with kubeaudit's audited checks. "
        "kubeaudit performs no mutation. Observed cluster state -> status "
        "'confirmed'; kubeaudit Criticality maps to severity (missing -> "
        "low). No arguments: the kubeconfig/context are fixed at "
        "construction."
    )
    binary = "kubeaudit"
    parameters = {"type": "object", "properties": {}}

    def __init__(self, kubeconfig: str, context: str = "",
                 timeout: int = _KUBEAUDIT_TIMEOUT):
        self.kubeconfig = kubeconfig
        self.context = context
        self.timeout = timeout

    def run(self, args: dict[str, Any]) -> ToolResult:
        cmd = ["kubeaudit", "--kubeconfig", self.kubeconfig]
        if self.context:
            cmd += ["--context", self.context]
        cmd += ["all", "-o", "json"]
        proc = self.shell(cmd, timeout=self.timeout)
        stdout = (proc.stdout or "").strip()
        if not stdout:
            if proc.returncode != 0:
                raise ToolError(f"kubeaudit failed (rc={proc.returncode}): "
                                f"{(proc.stderr or '')[:300]}")
            return ToolResult(ok=True, summary=(
                "kube_audit: kubeaudit found no misconfigurations "
                "(read-only audit)"))
        findings = parse_kubeaudit(stdout)
        if not findings:
            return ToolResult(
                ok=True,
                summary=("kube_audit: kubeaudit found no misconfigurations "
                         "(read-only audit)"),
                data={"count": 0, "findings": []},
                raw=stdout[:_RAW_CAP],
            )
        samples = ", ".join(f"{f['check']} [{f['severity']}]"
                            for f in findings[:3])
        return ToolResult(
            ok=True,
            summary=(f"kube_audit: {len(findings)} read-only audit finding(s); "
                     f"e.g. {samples}"),
            data={"count": len(findings), "findings": findings},
            raw=stdout[:_RAW_CAP],
        )
