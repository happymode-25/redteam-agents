"""Container/Kubernetes module (catalog section 15).

Covers: deterministic parsers with realistic trivy/kube-linter/kubeaudit
JSON, the verdict ladder (all three tools confirmed: version-range match,
manifest defect, observed cluster state), severity mapping with no
invented CVSS, read-only kube_audit command construction (fixed kubeconfig
+ context), the scanner evidence standard, redaction of registered
secrets in evidence, and schema containment (scan target fixed at
construction — no LLM-redirectable arguments).

No network, no real binaries, no cluster access: subprocess calls go
through a scripted runner.
"""

import json
import subprocess
import unittest
from pathlib import Path

from redteam.redact import redactor
from redteam.state import Finding, evidence_supported
from redteam.tools.base import LocalRunner, ToolError, set_runner
from redteam.tools.k8s import (ImageScanTool, KubeAuditTool, KubeLintTool,
                               kubeaudit_severity, linter_severity,
                               parse_kube_linter, parse_kubeaudit,
                               parse_trivy_image, trivy_severity)

TRIVY_JSON = json.dumps({
    "SchemaVersion": 2,
    "ArtifactName": "nginx:1.21",
    "ArtifactType": "container_image",
    "Results": [
        {"Target": "nginx:1.21 (debian 11.0)",
         "Vulnerabilities": [
             {"VulnerabilityID": "CVE-2022-1304",
              "PkgName": "zlib1g",
              "InstalledVersion": "1:1.2.11.dfsg-2",
              "FixedVersion": "1:1.2.11.dfsg-2+deb11u2",
              "Severity": "CRITICAL",
              "Title": "zlib: heap-based buffer over-read in inflate",
              "Description": "There is an off-by-one error in zlib...",
              "PrimaryURL": "https://avd.aquasec.com/cve/CVE-2022-1304"}]},
        {"Target": "nginx:1.21",
         "Vulnerabilities": [
             {"VulnerabilityID": "CVE-2021-23017",
              "PkgName": "nginx",
              "InstalledVersion": "1.21.0-1~bullseye",
              "Severity": "HIGH",
              "Title": "nginx: off-by-one in resolver",
              "PrimaryURL": "https://avd.aquasec.com/cve/CVE-2021-23017"}]},
    ],
})

TRIVY_JSON_SPARSE = json.dumps({
    "Results": [
        {"Target": "app:latest",
         "Vulnerabilities": [
             {"VulnerabilityID": "CVE-2020-1234",
              "PkgName": "openssl",
              "InstalledVersion": "1.1.1",
              "Severity": "UNKNOWN"}]},
    ],
})

TRIVY_JSON_CLEAN = json.dumps({
    "SchemaVersion": 2,
    "ArtifactName": "scratch:latest",
    "Results": [
        {"Target": "scratch:latest", "Vulnerabilities": []},
    ],
})

KUBE_LINTER_JSON = json.dumps({
    "Reports": [
        {"Check": "run-as-non-root",
         "Severity": "HIGH",
         "Description": "Container should run as non root user.",
         "Objects": [
             {"Object": {"Metadata": {"Name": "web", "Kind": "Deployment",
                                      "Namespace": "prod"},
                         "K8sObjects": ["Deployment/web"]},
              "File": {"Path": "deploy.yaml", "Line": 12}}],
         "Remediation": "Set runAsUser to a non-zero value in the container's "
                        "securityContext."},
        {"Check": "privileged-container",
         "Severity": "CRITICAL",
         "Objects": [
             {"Object": {"Metadata": {"Name": "log-agent", "Kind": "DaemonSet"}},
              "File": {"Path": "daemonset.yaml", "Line": 30}}],
         "Remediation": "Set securityContext.privileged to false."},
    ],
})

LONG_REMEDIATION = "A" * 200 + "TRUNCATED-TAIL-" + "B" * 100

KUBE_LINTER_LONG_REM_JSON = json.dumps({
    "Reports": [
        {"Check": "run-as-non-root", "Severity": "MEDIUM",
         "Objects": [
             {"Object": {"Metadata": {"Name": "worker", "Kind": "StatefulSet"}},
              "File": {"Path": "sts.yaml", "Line": 7}}],
         "Remediation": LONG_REMEDIATION},
    ],
})

KUBE_LINTER_CLEAN = json.dumps({"Reports": []})

KUBEAUDIT_JSON = json.dumps({
    "Results": [
        {"AuditResultName": "ErrorContainerNotReadOnly",
         "Verbosity": "error",
         "ResourceName": "web",
         "ContainerName": "nginx",
         "Namespace": "prod",
         "Image": "nginx:1.21",
         "Recommendation": "Set readOnlyRootFilesystem to true in the "
                           "container securityContext.",
         "Criticality": "Medium"},
        {"AuditResultName": "WarningImageTagTooLong",
         "Verbosity": "warning",
         "ResourceName": "batcher",
         "ContainerName": "app",
         "Namespace": "ops",
         "Image": "registry.example.internal/acme/batcher:release-2024-01",
         "Recommendation": "Use a short, immutable image digest."},
        {"AuditResultName": "ErrorPrivilegedContainer",
         "Verbosity": "error",
         "ResourceName": "agent",
         "ContainerName": "sidecar",
         "Namespace": "kube-system",
         "Recommendation": "Remove privileged mode from the container.",
         "Criticality": "High"},
    ],
})

KUBEAUDIT_CLEAN = json.dumps({"Results": []})


def _proc(cmd, rc=0, stdout="", stderr=""):
    return subprocess.CompletedProcess(cmd, rc, stdout, stderr)


class ScriptedRunner:
    """Fake subprocess runner keyed by binary name; all three k8s scanners
    read JSON from stdout (no report files)."""

    def __init__(self, responses):
        self.responses = responses
        self.calls = []

    def run(self, cmd, timeout=None, stdin=None):
        self.calls.append(cmd)
        name = Path(cmd[0]).name
        spec = self.responses.get(name)
        if spec is None:
            return _proc(cmd, rc=127, stderr=f"unexpected binary invoked: {name}")
        return _proc(cmd, rc=spec.get("rc", 0),
                     stdout=spec.get("stdout", ""), stderr=spec.get("stderr", ""))


def _supported(record: dict) -> bool:
    f = Finding(id="x", title=record["title"], severity=record["severity"],
                target=record["target"], evidence=record["evidence"],
                status=record["status"])
    return evidence_supported(f)


class TestSeverityHelpers(unittest.TestCase):
    def test_trivy_severity_bands(self):
        for label, sev in [("CRITICAL", "critical"), ("HIGH", "high"),
                           ("MEDIUM", "medium"), ("LOW", "low"),
                           ("UNKNOWN", "medium")]:
            self.assertEqual(trivy_severity(label), sev, label)

    def test_trivy_severity_defaults_to_medium(self):
        self.assertEqual(trivy_severity(""), "medium")
        self.assertEqual(trivy_severity("WAT"), "medium")

    def test_linter_severity_bands(self):
        for label, sev in [("CRITICAL", "critical"), ("HIGH", "high"),
                           ("MEDIUM", "medium"), ("LOW", "low"),
                           ("INFO", "info"), ("", "medium")]:
            self.assertEqual(linter_severity(label), sev, label)

    def test_kubeaudit_criticality_mapping(self):
        self.assertEqual(kubeaudit_severity("High"), "high")
        self.assertEqual(kubeaudit_severity("Medium"), "medium")
        self.assertEqual(kubeaudit_severity("Low"), "low")
        self.assertEqual(kubeaudit_severity(""), "low")   # missing -> low


class TestTrivyParser(unittest.TestCase):
    def setUp(self):
        self.findings = parse_trivy_image(TRIVY_JSON, "nginx:1.21")

    def test_confirmed_with_cve_ids(self):
        self.assertEqual(len(self.findings), 2)
        for f in self.findings:
            rec = f["record"]
            self.assertEqual(rec["status"], "confirmed")
            self.assertEqual(rec["cwe"], "")
            self.assertEqual(rec["cves"], f["cve"])
        self.assertEqual(self.findings[0]["cve"], "CVE-2022-1304")
        self.assertEqual(self.findings[1]["cve"], "CVE-2021-23017")

    def test_severity_map_and_upstream_label_carried(self):
        critical, high = self.findings
        self.assertEqual(critical["severity"], "critical")
        self.assertEqual(critical["scanner_severity"], "CRITICAL")
        self.assertEqual(high["severity"], "high")
        self.assertEqual(high["scanner_severity"], "HIGH")

    def test_target_composes_image_pkg_and_layer(self):
        self.assertEqual(
            self.findings[0]["record"]["target"],
            "nginx:1.21 :: zlib1g 1:1.2.11.dfsg-2 (nginx:1.21 (debian 11.0))")

    def test_fixed_vs_no_fix_evidence_wording(self):
        fixed, nofix = self.findings
        self.assertTrue(fixed["record"]["evidence"].startswith("scanner:"))
        self.assertIn("CVE-2022-1304 (CRITICAL) in zlib1g 1:1.2.11.dfsg-2",
                      fixed["record"]["evidence"])
        self.assertIn("fixed in 1:1.2.11.dfsg-2+deb11u2",
                      fixed["record"]["evidence"])
        self.assertIn("CVE-2021-23017 (HIGH) in nginx 1.21.0-1~bullseye",
                      nofix["record"]["evidence"])
        self.assertIn("fixed in none — no fix available",
                      nofix["record"]["evidence"])

    def test_remediation_branches(self):
        fixed, nofix = self.findings
        self.assertIn("Upgrade zlib1g", fixed["record"]["remediation"])
        self.assertIn("1:1.2.11.dfsg-2+deb11u2", fixed["record"]["remediation"])
        self.assertIn("No fixed version is published",
                      nofix["record"]["remediation"])
        self.assertIn("WAF", nofix["record"]["remediation"])

    def test_sparse_vuln_without_fixed_or_title(self):
        findings = parse_trivy_image(TRIVY_JSON_SPARSE, "app:latest")
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f["severity"], "medium")   # UNKNOWN -> medium
        self.assertEqual(f["fixed_version"], "")
        self.assertEqual(
            f["record"]["evidence"],
            "scanner: trivy matched CVE-2020-1234 (UNKNOWN) in openssl 1.1.1 "
            "on app:latest; fixed in none — no fix available")

    def test_empty_results_is_clean(self):
        self.assertEqual(parse_trivy_image(TRIVY_JSON_CLEAN, "scratch:latest"), [])
        self.assertEqual(
            parse_trivy_image('{"SchemaVersion": 2}', "scratch:latest"), [])

    def test_malformed_raises(self):
        with self.assertRaises(ToolError):
            parse_trivy_image("not json", "nginx:1.21")
        with self.assertRaises(ToolError):
            parse_trivy_image("[]", "nginx:1.21")

    def test_records_pass_evidence_standard(self):
        for f in self.findings:
            self.assertTrue(_supported(f["record"]))


class TestKubeLinterParser(unittest.TestCase):
    def setUp(self):
        self.findings = parse_kube_linter(KUBE_LINTER_JSON)

    def test_confirmed_with_check_ids_and_severity(self):
        self.assertEqual(len(self.findings), 2)
        run_as_non_root, privileged = self.findings
        self.assertEqual(run_as_non_root["check"], "run-as-non-root")
        self.assertEqual(run_as_non_root["severity"], "high")
        self.assertEqual(privileged["check"], "privileged-container")
        self.assertEqual(privileged["severity"], "critical")
        for f in self.findings:
            self.assertEqual(f["record"]["status"], "confirmed")
            self.assertEqual(f["record"]["cwe"], "")

    def test_object_metadata_in_target(self):
        self.assertEqual(self.findings[0]["record"]["target"],
                         "Deployment/web at deploy.yaml:12")
        self.assertEqual(self.findings[1]["record"]["target"],
                         "DaemonSet/log-agent at daemonset.yaml:30")

    def test_evidence_wording(self):
        ev = self.findings[0]["record"]["evidence"]
        self.assertTrue(ev.startswith(
            "scanner: kube-linter run-as-non-root (HIGH) on Deployment/web"
            " — remediation: Set runAsUser to a non-zero value"))
        self.assertTrue(_supported(self.findings[0]["record"]))

    def test_remediation_truncated_to_200_chars(self):
        f = parse_kube_linter(KUBE_LINTER_LONG_REM_JSON)[0]
        ev = f["record"]["evidence"]
        self.assertIn("A" * 200 + "...", ev)   # first 200 chars + ellipsis
        self.assertNotIn("TRUNCATED-TAIL", ev)

    def test_empty_reports_is_clean(self):
        self.assertEqual(parse_kube_linter(KUBE_LINTER_CLEAN), [])

    def test_malformed_raises(self):
        with self.assertRaises(ToolError):
            parse_kube_linter("nope")
        with self.assertRaises(ToolError):
            parse_kube_linter('{"Other": []}')


class TestKubeauditParser(unittest.TestCase):
    def setUp(self):
        self.findings = parse_kubeaudit(KUBEAUDIT_JSON)

    def test_confirmed_with_check_names(self):
        self.assertEqual(len(self.findings), 3)
        for f in self.findings:
            self.assertEqual(f["record"]["status"], "confirmed")
        self.assertEqual(self.findings[0]["check"], "ErrorContainerNotReadOnly")
        self.assertEqual(self.findings[1]["check"], "WarningImageTagTooLong")

    def test_criticality_mapping_incl_missing(self):
        medium, missing, high = self.findings
        self.assertEqual(medium["severity"], "medium")
        self.assertEqual(missing["severity"], "low")    # no Criticality field
        self.assertEqual(high["severity"], "high")

    def test_namespaced_target_includes_container(self):
        self.assertEqual(self.findings[0]["record"]["target"],
                         "prod/web container=nginx")
        self.assertEqual(self.findings[2]["record"]["target"],
                         "kube-system/agent container=sidecar")

    def test_evidence_quotes_recommendation_and_image(self):
        ev = self.findings[0]["record"]["evidence"]
        self.assertTrue(ev.startswith(
            "scanner: kubeaudit ErrorContainerNotReadOnly (error) on "
            "prod/web container=nginx [image nginx:1.21]"))
        self.assertIn("readOnlyRootFilesystem", ev)
        self.assertTrue(_supported(self.findings[0]["record"]))

    def test_empty_results_is_clean(self):
        self.assertEqual(parse_kubeaudit(KUBEAUDIT_CLEAN), [])

    def test_malformed_raises(self):
        with self.assertRaises(ToolError):
            parse_kubeaudit("}{")
        with self.assertRaises(ToolError):
            parse_kubeaudit('"a string"')


class TestToolRuns(unittest.TestCase):
    """End-to-end tool.run() with a scripted runner (exact argv + parsing)."""

    def setUp(self):
        self.runner = ScriptedRunner({})
        set_runner(self.runner)
        self.addCleanup(set_runner, LocalRunner())

    def test_image_scan_cmd_is_exact_and_scans_fixed_image(self):
        self.runner.responses["trivy"] = {"stdout": TRIVY_JSON}
        result = ImageScanTool("nginx:1.21").run({})
        self.assertTrue(result.ok)
        self.assertEqual(result.data["count"], 2)
        self.assertEqual(
            self.runner.calls[0],
            ["trivy", "image", "--format", "json", "--quiet",
             "--scanners", "vuln", "nginx:1.21"])

    def test_image_scan_summary_caps_three_samples(self):
        vulns = [{"VulnerabilityID": f"CVE-2024-{i:04d}", "PkgName": "p",
                  "InstalledVersion": "1", "Severity": "HIGH"}
                 for i in range(1, 5)]
        self.runner.responses["trivy"] = {
            "stdout": json.dumps({"Results": [{"Target": "img",
                                               "Vulnerabilities": vulns}]})}
        result = ImageScanTool("img:1").run({})
        self.assertEqual(result.data["count"], 4)   # full list in data
        for i in range(1, 4):
            self.assertIn(f"CVE-2024-{i:04d}", result.summary)
        self.assertNotIn("CVE-2024-0004", result.summary)

    def test_image_scan_clean_output(self):
        self.runner.responses["trivy"] = {"stdout": TRIVY_JSON_CLEAN}
        result = ImageScanTool("scratch:latest").run({})
        self.assertTrue(result.ok)
        self.assertIn("no known vulnerabilities", result.summary)
        self.assertEqual(result.data["count"], 0)

    def test_image_scan_failure_with_empty_stdout(self):
        self.runner.responses["trivy"] = {"rc": 1, "stderr": "no such image"}
        with self.assertRaises(ToolError):
            ImageScanTool("missing:latest").run({})

    def test_kube_lint_cmd_is_exact_and_parses(self):
        self.runner.responses["kube-linter"] = {"stdout": KUBE_LINTER_JSON}
        result = KubeLintTool("/srv/manifests").run({})
        self.assertTrue(result.ok)
        self.assertEqual(result.data["count"], 2)
        self.assertEqual(self.runner.calls[0],
                         ["kube-linter", "run", "/srv/manifests",
                          "--format", "json"])

    def test_kube_lint_tolerates_nonzero_rc_with_findings(self):
        # kube-linter can exit non-zero when a fail level is configured;
        # populated stdout is still parsed.
        self.runner.responses["kube-linter"] = {"stdout": KUBE_LINTER_JSON,
                                                "rc": 1}
        result = KubeLintTool("/srv/manifests").run({})
        self.assertEqual(result.data["count"], 2)

    def test_kube_lint_clean_output(self):
        self.runner.responses["kube-linter"] = {"stdout": KUBE_LINTER_CLEAN}
        result = KubeLintTool("/srv/manifests").run({})
        self.assertTrue(result.ok)
        self.assertIn("no kube-linter findings", result.summary)

    def test_kube_lint_failure_with_empty_stdout(self):
        self.runner.responses["kube-linter"] = {"rc": 2, "stderr": "boom"}
        with self.assertRaises(ToolError):
            KubeLintTool("/srv/manifests").run({})

    def test_kube_audit_cmd_with_context(self):
        self.runner.responses["kubeaudit"] = {"stdout": KUBEAUDIT_JSON}
        result = KubeAuditTool("/etc/kube/readonly.yaml",
                               context="staging").run({})
        self.assertTrue(result.ok)
        self.assertEqual(result.data["count"], 3)
        self.assertEqual(
            self.runner.calls[0],
            ["kubeaudit", "--kubeconfig", "/etc/kube/readonly.yaml",
             "--context", "staging", "all", "-o", "json"])

    def test_kube_audit_cmd_without_context_omits_flag(self):
        self.runner.responses["kubeaudit"] = {"stdout": KUBEAUDIT_JSON}
        KubeAuditTool("/etc/kube/readonly.yaml").run({})
        self.assertEqual(
            self.runner.calls[0],
            ["kubeaudit", "--kubeconfig", "/etc/kube/readonly.yaml",
             "all", "-o", "json"])
        self.assertNotIn("--context", self.runner.calls[0])

    def test_kube_audit_clean_output(self):
        self.runner.responses["kubeaudit"] = {"stdout": KUBEAUDIT_CLEAN}
        result = KubeAuditTool("/etc/kube/readonly.yaml").run({})
        self.assertTrue(result.ok)
        self.assertIn("no misconfigurations", result.summary)

    def test_kube_audit_failure_with_empty_stdout(self):
        self.runner.responses["kubeaudit"] = {"rc": 1, "stderr": "bad config"}
        with self.assertRaises(ToolError):
            KubeAuditTool("/etc/kube/readonly.yaml").run({})

    def test_unexpected_binary_is_a_tool_error(self):
        with self.assertRaises(ToolError):
            ImageScanTool("nginx:1.21").run({})   # runner has no trivy


class TestSchemaContainment(unittest.TestCase):
    """The scan target (image / dir / kubeconfig) is fixed at construction:
    the LLM sees no argument that could redirect any scanner."""

    def test_tools_expose_no_arguments(self):
        tools = [ImageScanTool("nginx:1.21"),
                 KubeLintTool("/srv/manifests"),
                 KubeAuditTool("/etc/kube/readonly.yaml", context="prod")]
        for tool in tools:
            self.assertEqual(tool.parameters,
                             {"type": "object", "properties": {}}, tool.name)


class TestRedaction(unittest.TestCase):
    def test_registered_secret_in_title_is_scrubbed_from_evidence(self):
        token = "AKIA1234567890ABCDEF"
        redactor.register(token)
        self.addCleanup(redactor.clear)
        sample = json.dumps({
            "Results": [
                {"Target": "img:1",
                 "Vulnerabilities": [
                     {"VulnerabilityID": "CVE-2024-9999",
                      "PkgName": "pkg",
                      "InstalledVersion": "1.0",
                      "Severity": "HIGH",
                      "Title": f"leaked key {token} baked into layer"}]}]})
        findings = parse_trivy_image(sample, "img:1")
        rec = findings[0]["record"]
        self.assertNotIn(token, rec["evidence"])
        self.assertIn("[REDACTED]", rec["evidence"])
        self.assertEqual(rec["status"], "confirmed")


if __name__ == "__main__":
    unittest.main()
