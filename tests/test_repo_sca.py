"""Phase 3.1 — Repo/SCA mode.

Covers: deterministic scanner parsers with realistic tool outputs, the
verdict ladder (secrets/dep/IaC confirmed, SAST suspected), scanner-side
redaction, root containment, the kill-switch-only local guard, coverage
matrix honesty keyed off used_tools, the evidence marker for static
scanner verdicts, and end-to-end pipeline wiring with a scripted model.

No network, no real scanner binaries: subprocess calls go through a
scripted runner; the model is a scripted router.
"""

import json
import subprocess
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from redteam.config import RepoConfig, load_config
from redteam.coverage import render_coverage
from redteam.repo import LocalScopeGuard, RepoScanner, run_repo_scan
from redteam.scope import Guard, KillSwitchEngaged, ScopeViolation
from redteam.state import evidence_supported
from redteam.tools.base import (LocalRunner, ToolError, set_runner)
from redteam.tools.sca import (DepScanTool, IacScanTool, SastScanTool,
                               SbomBuildTool, SecretScanTool,
                               cvss_to_severity, osv_severity, parse_checkov,
                               parse_gitleaks, parse_osv, parse_semgrep,
                               secret_severity)

ROOT = Path(__file__).resolve().parent.parent

GITLEAKS_JSON = json.dumps([
    {"RuleID": "aws-access-token", "Description": "AWS Access Key ID",
     "File": "src/config/settings.py", "StartLine": 12, "EndLine": 12,
     "Match": "AKIA************", "Secret": "*****", "Entropy": 4.5123,
     "Tags": ["aws", "key"], "Fingerprint": "src/config/settings.py:aws-access-token:12"},
    {"RuleID": "private-key", "Description": "Private Key",
     "File": "deploy/id_rsa", "StartLine": 1, "EndLine": 1,
     "Match": "-----BEGIN RSA PRIVATE KEY-----****", "Secret": "*****",
     "Tags": [], "Fingerprint": "deploy/id_rsa:private-key:1"},
    {"RuleID": "generic-api-key", "Description": "Generic API Key",
     "File": "app/keys.txt", "StartLine": 3, "EndLine": 3,
     "Match": "****", "Secret": "*****", "Entropy": 3.891,
     "Tags": [], "Fingerprint": "app/keys.txt:generic-api-key:3"},
])

SEMGREP_JSON = json.dumps({
    "version": "1.56.0",
    "results": [
        {"check_id": "python.sqlalchemy.security.sqlalchemy-execute-raw-query",
         "path": "app/db.py", "start": {"line": 44}, "end": {"line": 44},
         "extra": {
             "severity": "ERROR",
             "message": "Possible SQL injection.",
             "metadata": {
                 "cwe": ["CWE-89: Improper Neutralization of Special Elements "
                         "used in an SQL Command ('SQL Injection')"],
                 "owasp": ["A03:2021 - Injection"],
                 "confidence": "HIGH"},
             "lines": "        cursor.execute(f\"SELECT * FROM users WHERE id={uid}\")"}},
        {"check_id": "python.flask.security.app-run-debug",
         "path": "app/web.py", "start": {"line": 9}, "end": {"line": 9},
         "extra": {"severity": "WARNING",
                   "message": "Flask app appears to be run with debug=True",
                   "metadata": {}, "lines": "app.run(debug=True)"}},
    ],
})

OSV_JSON = json.dumps({
    "results": [
        {"source": {"path": "requirements.txt"},
         "packages": [
             {"package": {"name": "requests", "ecosystem": "PyPI",
                          "version": "2.19.0"},
              "vulnerabilities": [
                  {"id": "GHSA-x84v-xcm2-53pg",
                   "summary": "Leaking Authorization header to unintended hosts",
                   "aliases": ["CVE-2018-18074"],
                   "severity": [{"type": "CVSS_V3",
                                 "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"}],
                   "database_specific": {"severity": "HIGH"}},
                  {"id": "GHSA-numeric-1", "summary": "numeric score entry",
                   "severity": [{"type": "CVSS_V3", "score": "9.8"}]},
              ]},
         ]},
    ],
})

CHECKOV_JSON = json.dumps({
    "results": {
        "passed_checks": [{"check_id": "CKV_AWS_2"}],
        "failed_checks": [
            {"check_id": "CKV_AWS_20",
             "check_name": "S3 Bucket has an ACL defined which allows public READ access.",
             "file_path": "infra/main.tf", "line_number": 12,
             "resource": "aws_bucket.logs", "severity": "HIGH",
             "guideline": "https://docs.bridgecrew.io/docs/s3_1-public-read"},
            {"check_id": "CKV_AWS_18",
             "check_name": "Ensure the S3 bucket has access logging enabled",
             "file_path": "/infra/main.tf", "line_number": 12,
             "resource": "aws_bucket.logs",
             "guideline": "https://docs.bridgecrew.io/docs/s3_2-enable-logging"},
        ],
    },
    "summary": {"passed": 10, "failed": 2},
})

SYFT_JSON = json.dumps({
    "artifacts": [
        {"id": "a1", "name": "requests", "version": "2.31.0",
         "type": "python", "purl": "pkg:pypi/requests@2.31.0"},
        {"id": "a2", "name": "flask", "version": "3.0.0",
         "type": "python", "purl": "pkg:pypi/flask@3.0.0"},
        {"id": "a3", "name": "golang.org/x/sys", "version": "v0.15.0",
         "type": "go-module", "purl": "pkg:golang/golang.org/x/sys@v0.15.0"},
    ],
    "descriptor": {"name": "syft", "version": "1.0.0"},
})


def _proc(cmd, rc=0, stdout="", stderr=""):
    return subprocess.CompletedProcess(cmd, rc, stdout, stderr)


class ScriptedRunner:
    """Fake subprocess runner keyed by binary name. Emulates gitleaks'
    report-file behavior when 'report' is given (the real tool writes JSON
    to --report-path, not stdout)."""

    def __init__(self, responses):
        self.responses = responses
        self.calls = []

    def run(self, cmd, timeout=None, stdin=None):
        self.calls.append(cmd)
        name = Path(cmd[0]).name
        spec = self.responses.get(name)
        if spec is None:
            return _proc(cmd, rc=127, stderr=f"unexpected binary invoked: {name}")
        if "report" in spec:
            Path(cmd[cmd.index("--report-path") + 1]).write_text(
                spec["report"], encoding="utf-8")
        return _proc(cmd, rc=spec.get("rc", 0),
                     stdout=spec.get("stdout", ""), stderr=spec.get("stderr", ""))


def make_cfg(tmp=None, **repo_overrides):
    cfg = load_config(ROOT / "config.example.yaml")
    tmp = Path(tmp or tempfile.mkdtemp())
    cfg = replace(cfg, safety=replace(cfg.safety,
                                      artifacts_dir=str(tmp / "art"),
                                      cassette_dir=str(tmp / "cass"),
                                      runner="local"))
    if repo_overrides:
        cfg = replace(cfg, repo=replace(cfg.repo, **repo_overrides))
    return cfg, tmp


def tmp_root() -> Path:
    return Path(tempfile.mkdtemp()).resolve()


class TestSeverityHelpers(unittest.TestCase):
    def test_cvss_bands(self):
        for score, sev in [(9.8, "critical"), (9.0, "critical"), (7.5, "high"),
                           (7.0, "high"), (5.4, "medium"), (2.0, "low"),
                           (0.0, "info")]:
            self.assertEqual(cvss_to_severity(score), sev, score)

    def test_secret_severity_policy(self):
        for rule in ("aws-access-token", "private-key", "github-token",
                     "secret-key", "stripe_token"):
            self.assertEqual(secret_severity(rule, []), "critical", rule)
        self.assertEqual(secret_severity("generic-api-key", []), "high")
        self.assertEqual(secret_severity("slack-webhook", ["slack"]), "high")

    def test_osv_severity_label_beats_vector(self):
        vuln = {"severity": [{"score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"}],
                "database_specific": {"severity": "HIGH"}}
        self.assertEqual(osv_severity(vuln), ("high", ""))

    def test_osv_severity_numeric_score(self):
        vuln = {"severity": [{"score": "9.8"}]}
        self.assertEqual(osv_severity(vuln), ("critical", "9.8"))

    def test_osv_severity_vector_without_label_is_medium(self):
        vuln = {"severity": [{"score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"}]}
        sev, cvss = osv_severity(vuln)
        self.assertEqual(sev, "medium")       # no base score computed from a vector
        self.assertIn("CVSS:3.1", cvss)

    def test_osv_severity_default(self):
        self.assertEqual(osv_severity({}), ("medium", ""))


class TestGitleaksParser(unittest.TestCase):
    def setUp(self):
        self.root = tmp_root()
        self.findings = parse_gitleaks(GITLEAKS_JSON, self.root)

    def test_severity_policy(self):
        by_rule = {f["rule"]: f["severity"] for f in self.findings}
        self.assertEqual(by_rule["aws-access-token"], "critical")
        self.assertEqual(by_rule["private-key"], "critical")
        self.assertEqual(by_rule["generic-api-key"], "high")

    def test_record_is_confirmed_with_scanner_marker(self):
        rec = self.findings[0]["record"]
        self.assertEqual(rec["status"], "confirmed")
        self.assertEqual(rec["cwe"], "CWE-798")
        self.assertEqual(rec["target"], "src/config/settings.py:12")
        self.assertTrue(rec["evidence"].startswith("scanner:"))
        self.assertIn("LIVENESS NOT TESTED", rec["evidence"])
        self.assertIn("Rotate", rec["remediation"])

    def test_evidence_passes_the_evidence_standard(self):
        from redteam.state import Finding
        f = Finding(id="x", title="t", severity="high", target="t",
                    evidence=self.findings[0]["record"]["evidence"],
                    status="confirmed")
        self.assertTrue(evidence_supported(f))

    def test_no_secret_value_anywhere(self):
        blob = json.dumps(self.findings)
        self.assertNotIn("AKIA", blob)
        self.assertIn("***redacted***", blob)

    def test_paths_rendered_repo_relative(self):
        targets = {f["record"]["target"] for f in self.findings}
        self.assertEqual(targets, {
            "src/config/settings.py:12", "deploy/id_rsa:1", "app/keys.txt:3"})
        for f in self.findings:
            self.assertEqual(Path(f["file"]).as_posix(), f["file"].replace("\\", "/"))

    def test_malformed_output_raises(self):
        with self.assertRaises(ToolError):
            parse_gitleaks("not json", self.root)
        with self.assertRaises(ToolError):
            parse_gitleaks('{"unexpected": "shape"}', self.root)


class TestSemgrepParser(unittest.TestCase):
    def setUp(self):
        self.root = tmp_root()
        self.findings = parse_semgrep(SEMGREP_JSON, self.root)

    def test_verdicts_are_suspected_static_only(self):
        for f in self.findings:
            self.assertEqual(f["record"]["status"], "suspected")
            self.assertIn("Static pattern only", f["record"]["evidence"])

    def test_severity_and_cwe_mapping(self):
        sqli, debug = self.findings
        self.assertEqual(sqli["severity"], "high")
        self.assertEqual(sqli["cwe"], "CWE-89")
        self.assertEqual(sqli["record"]["cwe"], "CWE-89")
        self.assertEqual(debug["severity"], "medium")
        self.assertEqual(debug["record"]["cwe"], "")

    def test_evidence_quotes_code_context(self):
        self.assertIn("cursor.execute", self.findings[0]["record"]["evidence"])


class TestOsvParser(unittest.TestCase):
    def setUp(self):
        self.root = tmp_root()
        self.findings = parse_osv(OSV_JSON, self.root)

    def test_confirmed_with_ids(self):
        gh, numeric = self.findings
        self.assertEqual(gh["record"]["status"], "confirmed")
        self.assertIn("CVE-2018-18074", gh["record"]["cves"])
        self.assertIn("GHSA-x84v-xcm2-53pg", gh["ids"])
        self.assertEqual(gh["record"]["severity"], "high")
        self.assertEqual(numeric["record"]["severity"], "critical")

    def test_target_names_package_and_file(self):
        gh = self.findings[0]
        self.assertEqual(gh["record"]["target"],
                         "requirements.txt (requests==2.19.0)")
        self.assertIn("requests==2.19.0", gh["record"]["evidence"])

    def test_clean_and_malformed(self):
        self.assertEqual(parse_osv('{"results": []}', self.root), [])
        with self.assertRaises(ToolError):
            parse_osv("nope", self.root)
        with self.assertRaises(ToolError):
            parse_osv('{"other": []}', self.root)


class TestCheckovParser(unittest.TestCase):
    def setUp(self):
        self.root = tmp_root()
        self.findings = parse_checkov(CHECKOV_JSON, self.root)

    def test_confirmed_misconfig_with_severity(self):
        first = self.findings[0]
        self.assertEqual(first["record"]["status"], "confirmed")
        self.assertEqual(first["severity"], "high")
        self.assertTrue(first["record"]["evidence"].startswith("scanner: checkov CKV_AWS_20"))
        self.assertIn("infra/main.tf:12", first["record"]["target"])
        self.assertIn("public-read", first["record"]["remediation"])

    def test_missing_severity_defaults_to_medium(self):
        self.assertEqual(self.findings[1]["severity"], "medium")

    def test_leading_slash_paths_normalized(self):
        self.assertEqual(self.findings[1]["file"], "infra/main.tf")

    def test_malformed(self):
        with self.assertRaises(ToolError):
            parse_checkov("[]", self.root)


class TestSbomTool(unittest.TestCase):
    def setUp(self):
        self.art = Path(tempfile.mkdtemp())
        self.tool = SbomBuildTool(tmp_root(), RepoConfig(), self.art)
        set_runner(ScriptedRunner({"syft": {"stdout": SYFT_JSON}}))
        self.addCleanup(set_runner, LocalRunner())

    def test_inventory_counts_and_artifact(self):
        result = self.tool.run({})
        self.assertTrue(result.ok)
        self.assertEqual(result.data["component_count"], 3)
        self.assertEqual(result.data["by_type"], {"go-module": 1, "python": 2})
        artifact = Path(result.data["artifact"])
        self.assertTrue(artifact.exists())
        self.assertTrue(artifact.name.startswith("sbom-"))
        self.assertEqual(json.loads(artifact.read_text(encoding="utf-8"))
                         ["descriptor"]["name"], "syft")

    def test_no_finding_is_produced(self):
        result = self.tool.run({})
        self.assertNotIn("findings", result.data)


class TestToolRuns(unittest.TestCase):
    """End-to-end tool.run() with a scripted runner (cmd + parsing)."""

    def setUp(self):
        self.root = tmp_root()
        self.runner = ScriptedRunner({})
        set_runner(self.runner)
        self.addCleanup(set_runner, LocalRunner())

    def test_gitleaks_uses_report_file_and_forces_redaction(self):
        self.runner.responses["gitleaks"] = {"report": GITLEAKS_JSON}
        tool = SecretScanTool(self.root, RepoConfig())
        result = tool.run({})
        self.assertTrue(result.ok)
        self.assertEqual(result.data["count"], 3)
        cmd = self.runner.calls[0]
        self.assertIn("--redact", cmd)
        self.assertEqual(cmd[cmd.index("--exit-code") + 1], "0")
        self.assertIn(str(self.root), cmd)
        # exclusion flags for the configured noisy dirs
        self.assertIn("--exclude-path", cmd)

    def test_gitleaks_clean_and_failure(self):
        self.runner.responses["gitleaks"] = {"report": "[]"}
        result = SecretScanTool(self.root, RepoConfig()).run({})
        self.assertTrue(result.ok)
        self.assertIn("no hardcoded secrets", result.summary)

        self.runner.responses["gitleaks"] = {"rc": 2, "stderr": "boom"}
        with self.assertRaises(ToolError):
            SecretScanTool(self.root, RepoConfig()).run({})

    def test_semgrep_forces_metrics_off(self):
        self.runner.responses["semgrep"] = {"stdout": SEMGREP_JSON}
        tool = SastScanTool(self.root, RepoConfig())
        result = tool.run({})
        self.assertEqual(result.data["count"], 2)
        cmd = self.runner.calls[0]
        self.assertIn("--metrics=off", cmd)
        self.assertEqual(cmd[-1], str(self.root))   # root is the scan target
        self.assertIn("--exclude=.git", cmd)

    def test_osv_online_vs_offline_flag(self):
        self.runner.responses["osv-scanner"] = {"stdout": OSV_JSON, "rc": 1}
        DepScanTool(self.root, RepoConfig(osv_online=True)).run({})
        self.assertNotIn("--offline", self.runner.calls[0])

        self.runner.responses["osv-scanner"] = {"stdout": OSV_JSON, "rc": 1}
        result = DepScanTool(self.root, RepoConfig(osv_online=False)).run({})
        self.assertIn("--offline", self.runner.calls[1])
        self.assertIn("offline", result.summary)
        self.assertIn("offline", result.data["network"])

    def test_osv_hard_failure(self):
        self.runner.responses["osv-scanner"] = {"rc": 3, "stderr": "db missing"}
        with self.assertRaises(ToolError):
            DepScanTool(self.root, RepoConfig()).run({})

    def test_checkov_cmd_and_run(self):
        self.runner.responses["checkov"] = {"stdout": CHECKOV_JSON}
        result = IacScanTool(self.root, RepoConfig()).run({})
        self.assertEqual(result.data["count"], 2)
        cmd = self.runner.calls[0]
        self.assertEqual(cmd[cmd.index("-d") + 1], str(self.root))
        self.assertIn("--exclude-dir", cmd)

    def test_unexpected_binary_is_a_tool_error(self):
        with self.assertRaises(ToolError):
            IacScanTool(self.root, RepoConfig()).run({})  # runner has no checkov


class TestScannerSchemas(unittest.TestCase):
    """Containment guarantee: the LLM cannot point a scanner anywhere —
    the root is fixed at construction and the schemas take no arguments."""

    def test_tools_expose_no_path_arguments(self):
        root, cfg = tmp_root(), RepoConfig()
        tools = [SecretScanTool(root, cfg), SastScanTool(root, cfg),
                 DepScanTool(root, cfg), IacScanTool(root, cfg),
                 SbomBuildTool(root, cfg, Path(tempfile.mkdtemp()))]
        for tool in tools:
            self.assertEqual(tool.parameters,
                             {"type": "object", "properties": {}}, tool.name)


class TestRootValidation(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp()).resolve()
        self.allowed = self.tmp / "allowed"
        self.allowed.mkdir()
        (self.allowed / "sub").mkdir()
        self.outside = self.tmp / "outside"
        self.outside.mkdir()
        self.file = self.tmp / "afile.txt"
        self.file.write_text("x", encoding="utf-8")

    def _cfg(self, allowlist):
        cfg, _ = make_cfg()
        return replace(cfg, repo=replace(cfg.repo, path_allowlist=allowlist))

    def test_inside_allowlist(self):
        root = RepoScanner._validate_root(self._cfg([str(self.allowed)]),
                                          self.allowed)
        self.assertEqual(root, self.allowed)

    def test_nested_inside_allowlist(self):
        root = RepoScanner._validate_root(self._cfg([str(self.allowed)]),
                                          self.allowed / "sub")
        self.assertEqual(root, self.allowed / "sub")

    def test_outside_allowlist_refused(self):
        with self.assertRaises(ScopeViolation):
            RepoScanner._validate_root(self._cfg([str(self.allowed)]),
                                       self.outside)

    def test_dotdot_traversal_refused(self):
        sneaky = self.allowed / ".." / "outside"
        with self.assertRaises(ScopeViolation):
            RepoScanner._validate_root(self._cfg([str(self.allowed)]), sneaky)

    def test_empty_allowlist_accepts_any_existing_dir(self):
        root = RepoScanner._validate_root(self._cfg([]), self.outside)
        self.assertEqual(root, self.outside)

    def test_nonexistent_and_file_refused(self):
        cfg = self._cfg([])
        with self.assertRaises(ValueError):
            RepoScanner._validate_root(cfg, self.tmp / "nope")
        with self.assertRaises(ValueError):
            RepoScanner._validate_root(cfg, self.file)

    def test_run_repo_scan_maps_violation_to_system_exit(self):
        cfg = self._cfg([str(self.allowed)])
        with self.assertRaises(SystemExit):
            run_repo_scan(cfg, self.outside)


class TestLocalScopeGuard(unittest.TestCase):
    def setUp(self):
        cfg, self.tmp = make_cfg()
        self.guard = LocalScopeGuard(Guard.from_config(cfg.scope, self.tmp / "art"))

    def test_run_executes_fn_and_returns_result(self):
        self.assertEqual(self.guard.run("src/app.py:12", lambda: 42), 42)

    def test_file_labels_are_not_scope_checked(self):
        # a web Guard would reject this as a non-host target; the repo
        # stand-in accepts it (no network tools exist in this registry)
        self.assertEqual(self.guard.authorize("src/config/settings.py:12"),
                         "src/config/settings.py:12")

    def test_kill_switch_still_enforced(self):
        self.guard.kill.trip()
        with self.assertRaises(KillSwitchEngaged):
            self.guard.run("x", lambda: None)
        with self.assertRaises(KillSwitchEngaged):
            self.guard.authorize("x")


class TestEvidenceMarker(unittest.TestCase):
    def test_scanner_marker_supports_confirmed(self):
        from redteam.state import Finding
        f = Finding(id="x", title="t", severity="high", target="t",
                    status="confirmed",
                    evidence="scanner: gitleaks rule aws-access-token matched at "
                             "src/s.py:12 (AWS Access Key; redacted)")
        self.assertTrue(evidence_supported(f))

    def test_too_short_still_rejected(self):
        from redteam.state import Finding
        f = Finding(id="x", title="t", severity="high", target="t",
                    status="confirmed", evidence="scanner: x")
        self.assertFalse(evidence_supported(f))


def _coverage(used, identities=False):
    return render_coverage(identities=identities, tools_used=used)


def _row(text, section):
    for line in text.splitlines():
        if line.startswith(f"| {section}"):
            return line
    raise AssertionError(f"row {section} not found")


class TestCoverageHonesty(unittest.TestCase):
    """Repo/SCA rows key strictly off scanners that ran — with NO identities
    (repo mode has none) and never off config presence."""

    def test_section_13_upgrades_on_dep_scan(self):
        line = _row(_coverage({"dep_scan"}), "13.")
        self.assertIn("PARTIAL", line)
        self.assertIn("osv-scanner", line)
        self.assertIn("lockfiles", line)

    def test_section_13_sbom_only_is_inventory_not_vuln_matching(self):
        line = _row(_coverage({"sbom_build"}), "13.")
        self.assertIn("no vulnerability matching", line)

    def test_section_13_untouched_without_repo_tools(self):
        line = _row(_coverage({"nuclei_scan"}), "13.")
        self.assertIn("OUT OF BAND", line)

    def test_section_24_checked_when_both_scanners_ran(self):
        line = _row(_coverage({"secret_scan", "sast_scan"}), "24.")
        self.assertIn("CHECKED", line)
        self.assertIn("redacted BY THE SCANNER", line)
        self.assertIn("suspected", line)

    def test_section_24_partial_when_one_scanner_ran(self):
        line = _row(_coverage({"secret_scan"}), "24.")
        self.assertIn("PARTIAL", line)
        self.assertIn("gitleaks secret scan ran this run", line)
        self.assertNotIn("CHECKED", line)

    def test_section_24_honest_when_repo_mode_but_no_scanners(self):
        line = _row(_coverage({"sbom_build", "record_finding"}), "24.")
        self.assertIn("did NOT happen", line)

    def test_section_24_mentions_vcs_check_only_when_it_ran(self):
        line = _row(_coverage({"secret_scan", "sast_scan", "exposed_vcs"}), "24.")
        self.assertIn("exposed VCS", line)
        line = _row(_coverage({"secret_scan", "sast_scan"}), "24.")
        self.assertNotIn("exposed VCS", line)

    def test_section_15_on_iac_scan(self):
        line = _row(_coverage({"iac_scan"}), "15.")
        self.assertIn("PARTIAL", line)
        self.assertIn("checkov", line)

    def test_section_12_appends_iac(self):
        line = _row(_coverage({"iac_scan"}), "12.")
        self.assertIn("+ checkov IaC misconfigurations", line)
        self.assertNotIn("checkov", _row(_coverage(set()), "12."))

    def test_repo_rows_apply_without_identities_flag(self):
        text = _coverage({"dep_scan", "iac_scan"})
        self.assertIn("osv-scanner", text)
        self.assertIn("checkov", text)


class _ScriptedProvider:
    def __init__(self, replies):
        self.replies = list(replies)
        self.model = "scripted"

    def complete(self, system, messages):
        if self.replies:
            return self.replies.pop(0)
        return '{"action": "final", "answer": "(script exhausted)"}'


class _ScriptedRouter:
    def __init__(self, replies_by_role):
        self._replies = replies_by_role

    def for_role(self, role):
        return _ScriptedProvider(self._replies.get(role, []))


class TestPipeline(unittest.TestCase):
    """End-to-end wiring: scripted model + scripted runner, real agents,
    real report render."""

    def setUp(self):
        self.repo = Path(tempfile.mkdtemp()).resolve()
        (self.repo / "src").mkdir()
        self.cfg, self.tmp = make_cfg()

    def _scanner(self, replies):
        scanner = RepoScanner(self.cfg, self.repo, mode="live",
                              router=_ScriptedRouter(replies))
        # construction calls configure_runner(); swap in the fake after
        set_runner(ScriptedRunner({}))
        self.addCleanup(set_runner, LocalRunner())
        return scanner

    def test_pipeline_records_finding_and_writes_report(self):
        evidence = ("scanner: gitleaks rule aws-access-token matched at "
                    "src/settings.py:12 (AWS Access Key ID; the match is redacted "
                    "by the scanner itself — no secret value was seen or stored). "
                    "LIVENESS NOT TESTED: the credential was reported, never used.")
        record_call = json.dumps({
            "action": "tool", "tool": "record_finding", "args": {
                "title": "Hardcoded credential: aws-access-token in src/settings.py",
                "severity": "critical", "status": "confirmed",
                "cwe": "CWE-798", "target": "src/settings.py:12",
                "evidence": evidence,
                "remediation": "Rotate the exposed credential and load secrets "
                               "from an env var. Liveness not tested.",
            }})
        scanner = self._scanner({
            "repo": [record_call,
                     '{"action": "final", "answer": "Repo analysis complete."}'],
            "reporter": ['{"action": "final", "answer": "Narrative for the report."}'],
        })
        report_path = scanner.run()

        self.assertTrue(report_path.exists())
        self.assertEqual(report_path.parent,
                         Path(self.cfg.safety.artifacts_dir).resolve())
        self.assertEqual(len(scanner.state.findings), 1)
        finding = scanner.state.findings[0]
        self.assertEqual(finding.status, "confirmed")   # scanner: marker holds
        self.assertEqual(finding.cwe, "CWE-798")
        self.assertIn("record_finding", scanner.used_tools)
        audit = Path(self.cfg.safety.artifacts_dir) / "audit.jsonl"
        self.assertTrue(audit.exists())

        text = report_path.read_text(encoding="utf-8")
        self.assertIn("Coverage Matrix", text)
        self.assertIn("Hardcoded credential", text)

    def test_findings_json_written(self):
        scanner = self._scanner({
            "repo": ['{"action": "final", "answer": "nothing to record"}'],
            "reporter": ['{"action": "final", "answer": "n"}'],
        })
        scanner.run()
        findings_files = list(Path(self.cfg.safety.artifacts_dir).glob("findings-*.json"))
        self.assertEqual(len(findings_files), 1)
        saved = json.loads(findings_files[0].read_text(encoding="utf-8"))
        self.assertEqual(saved["findings"], [])

    def test_registry_has_exactly_the_local_toolset(self):
        scanner = self._scanner({})
        names = {"secret_scan", "sast_scan", "dep_scan", "iac_scan",
                 "sbom_build", "record_finding"}
        got = {scanner.registry.get(n) is not None for n in names}
        self.assertEqual(got, {True})
        # no network-capable tool may exist in repo mode
        for leaked in ("http_request", "nuclei_scan", "nmap_scan",
                       "session_login", "race_burst"):
            self.assertIsNone(scanner.registry.get(leaked))

    def test_missing_scanners_reported(self):
        scanner = self._scanner({})
        missing = scanner.missing_scanners()
        for entry in missing:
            self.assertIn("not found on PATH", entry)


if __name__ == "__main__":
    unittest.main()
