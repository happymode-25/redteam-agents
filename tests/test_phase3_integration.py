"""Phase-3 integration: the SHARED wiring that ties the subagent-built
modules (sections 7/14/15/17/19) into the platform.

The modules have their own unit tests. This file covers only what the
integration layer added:
  * config parsing + fail-closed validation for the five new sections,
  * conditional registration in the orchestrator (configured => registered,
    not configured => absent; the ad_collect operator gate is honored),
  * coverage honesty: rows upgrade strictly off tools that RAN this run,
    never off configuration.
"""

from __future__ import annotations

import os
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest import mock

from redteam.config import (ADConfig, AIConfig, CloudConfig, K8sConfig,
                            MobileConfig, load_config)
from redteam.coverage import render_coverage
from redteam.orchestrator import Orchestrator

ROOT = Path(__file__).resolve().parent.parent
EXAMPLE = ROOT / "config.example.yaml"

# every tool the integration registers (3+2+2+2+3)
PHASE3_TOOL_NAMES = {
    "image_scan", "kube_lint", "kube_audit",
    "ai_endpoint_probe", "prompt_probe",
    "bucket_exposure", "cloud_posture_report",
    "ad_collect", "ad_analyze",
    "manifest_audit", "apk_badging", "decompile_secrets",
}


def load_with(extra: str):
    """config.example.yaml + one appended ACTIVE section. The example keeps
    its Phase-3 sections commented out, so there is no duplicate key."""
    text = EXAMPLE.read_text(encoding="utf-8") + "\n" + extra + "\n"
    path = Path(tempfile.mkdtemp()) / "config.yaml"
    path.write_text(text, encoding="utf-8")
    return load_config(path)


def base_cfg():
    return load_config(EXAMPLE)


def present(orch: Orchestrator) -> set[str]:
    return {n for n in PHASE3_TOOL_NAMES if orch.registry.get(n)}


def row_line(md: str, prefix: str) -> str:
    for line in md.splitlines():
        if line.startswith(f"| {prefix} "):
            return line
    raise AssertionError(f"no coverage row starting with {prefix!r}")


class TestConfigParsing(unittest.TestCase):
    def test_example_defaults_are_empty(self):
        cfg = base_cfg()
        self.assertEqual(cfg.k8s, K8sConfig())
        self.assertEqual(cfg.ai, AIConfig())
        self.assertEqual(cfg.cloud, CloudConfig())
        self.assertEqual(cfg.ad, ADConfig())
        self.assertEqual(cfg.mobile, MobileConfig())

    def test_k8s_section_parses(self):
        cfg = load_with("k8s:\n  image: nginx:1.25\n  lint_dir: ./k8s\n"
                        "  kubeconfig: kube.config\n  context: prod\n")
        self.assertEqual(cfg.k8s.image, "nginx:1.25")
        self.assertEqual(cfg.k8s.lint_dir, "./k8s")
        self.assertEqual(cfg.k8s.kubeconfig, "kube.config")
        self.assertEqual(cfg.k8s.context, "prod")

    def test_ai_section_parses_and_normalizes_endpoint(self):
        cfg = load_with("ai:\n  endpoint: https://ai.shop.test/v1/\n"
                        "  model: test-model\n  timeout: 30\n")
        self.assertEqual(cfg.ai.endpoint, "https://ai.shop.test/v1")  # rstripped
        self.assertEqual(cfg.ai.model, "test-model")
        self.assertEqual(cfg.ai.timeout, 30)

    def test_ai_endpoint_requires_http_scheme(self):
        with self.assertRaises(ValueError) as ctx:
            load_with("ai:\n  endpoint: ftp://ai.shop.test\n")
        self.assertIn("http(s)", str(ctx.exception))

    def test_ai_auth_env_refused_when_var_unset(self):
        var = "RTA_PHASE3_UNSET_TOKEN"
        with mock.patch.dict(os.environ):
            os.environ.pop(var, None)
            with self.assertRaises(ValueError) as ctx:
                load_with(f"ai:\n  endpoint: https://ai.shop.test\n"
                          f"  auth_env: {var}\n")
        self.assertIn(var, str(ctx.exception))

    def test_ai_auth_env_accepted_when_var_set(self):
        var = "RTA_PHASE3_SET_TOKEN"
        with mock.patch.dict(os.environ, {var: "secret-value"}):
            cfg = load_with(f"ai:\n  endpoint: https://ai.shop.test\n"
                            f"  auth_env: {var}\n")
        self.assertEqual(cfg.ai.auth_env, var)
        # the VALUE never lands in the config — only the env var NAME
        self.assertNotIn("secret-value", repr(cfg))

    def test_cloud_report_requires_kind(self):
        with self.assertRaises(ValueError) as ctx:
            load_with("cloud:\n  report_path: ./prowler.json\n")
        self.assertIn("together", str(ctx.exception))

    def test_cloud_kind_requires_report(self):
        with self.assertRaises(ValueError):
            load_with("cloud:\n  report_kind: prowler\n")

    def test_cloud_kind_rejected_when_unknown(self):
        with self.assertRaises(ValueError) as ctx:
            load_with("cloud:\n  report_path: ./r.json\n  report_kind: aws\n")
        self.assertIn("prowler|scout", str(ctx.exception))

    def test_cloud_section_parses(self):
        cfg = load_with("cloud:\n  org_hints: [acme, acme-corp]\n"
                        "  report_path: ./r.json\n  report_kind: PROWLER\n"
                        "  timeout: 5\n")
        self.assertEqual(cfg.cloud.org_hints, ["acme", "acme-corp"])
        self.assertEqual(cfg.cloud.report_kind, "prowler")  # lowercased
        self.assertEqual(cfg.cloud.timeout, 5)

    def test_ad_collect_requires_dc_and_domain(self):
        with self.assertRaises(ValueError) as ctx:
            load_with("ad:\n  collect: true\n  dc_ip: 10.0.0.5\n")
        self.assertIn("ad.dc_ip and ad.domain", str(ctx.exception))

    def test_ad_collect_accepts_full_config(self):
        cfg = load_with("ad:\n  collect: true\n  dc_ip: 10.0.0.5\n"
                        "  domain: corp.test\n  analyze_report: bh.zip\n"
                        "  max_depth: 4\n")
        self.assertTrue(cfg.ad.collect)
        self.assertEqual(cfg.ad.domain, "corp.test")
        self.assertEqual(cfg.ad.analyze_report, "bh.zip")
        self.assertEqual(cfg.ad.max_depth, 4)

    def test_mobile_section_parses(self):
        cfg = load_with("mobile:\n  manifest_path: AndroidManifest.xml\n"
                        "  apk_path: app.apk\n  decompiled_dir: ./src\n")
        self.assertEqual(cfg.mobile.apk_path, "app.apk")
        self.assertEqual(cfg.mobile.manifest_path, "AndroidManifest.xml")
        self.assertEqual(cfg.mobile.decompiled_dir, "./src")


class TestRegistration(unittest.TestCase):
    def test_default_config_registers_no_phase3_tools(self):
        self.assertEqual(present(Orchestrator(base_cfg())), set())

    def test_full_config_registers_every_phase3_tool(self):
        cfg = replace(
            base_cfg(),
            k8s=K8sConfig(image="nginx:1.25", lint_dir="./k8s",
                          kubeconfig="kube.config", context="prod"),
            ai=AIConfig(endpoint="https://ai.shop.test", model="m1",
                        timeout=5),
            cloud=CloudConfig(org_hints=["acme"], report_path="r.json",
                              report_kind="prowler"),
            ad=ADConfig(collect=True, dc_ip="10.0.0.5", domain="corp.test",
                        analyze_report="bh.zip"),
            mobile=MobileConfig(manifest_path="m.xml", apk_path="a.apk",
                                decompiled_dir="./src"),
        )
        self.assertEqual(present(Orchestrator(cfg)), PHASE3_TOOL_NAMES)

    def test_only_configured_inputs_register(self):
        cfg = replace(base_cfg(), k8s=K8sConfig(image="nginx:1.25"))
        self.assertEqual(present(Orchestrator(cfg)), {"image_scan"})

    def test_ai_tools_register_together_and_only_with_endpoint(self):
        ai_only = replace(base_cfg(), ai=AIConfig(endpoint="http://llm.local"))
        self.assertEqual(present(Orchestrator(ai_only)),
                         {"ai_endpoint_probe", "prompt_probe"})
        # ai config WITHOUT an endpoint registers nothing
        no_endpoint = replace(base_cfg(), ai=AIConfig(model="m"))
        self.assertEqual(present(Orchestrator(no_endpoint)), set())

    def test_ad_collect_registration_honors_operator_gate(self):
        gated = replace(base_cfg(),
                        ad=ADConfig(dc_ip="10.0.0.5", domain="corp.test"))
        tool = Orchestrator(gated).registry.get("ad_collect")
        self.assertIsNotNone(tool)
        # registry entries are FixtureTool wrappers — inspect the real tool
        self.assertFalse(tool.inner.enabled)   # registered but refuses to run

        open_gate = replace(base_cfg(),
                            ad=ADConfig(collect=True, dc_ip="10.0.0.5",
                                        domain="corp.test"))
        tool = Orchestrator(open_gate).registry.get("ad_collect")
        self.assertIsNotNone(tool)
        self.assertTrue(tool.inner.enabled)


class TestCoverageHonesty(unittest.TestCase):
    def render(self, used=frozenset()) -> str:
        return render_coverage(identities=False, tools_used=used)

    def test_phase3_rows_never_claim_without_running_tools(self):
        md = self.render()
        for prefix, tool_markers in {
            "7.": ("bucket_exposure", "cloud_posture_report"),
            "14.": ("manifest_audit", "apk_badging", "decompile_secrets"),
            "15.": ("image_scan", "kube_lint", "kube_audit"),
            "17.": ("ad_collect", "ad_analyze"),
            "19.": ("ai_endpoint_probe", "prompt_probe"),
        }.items():
            line = row_line(md, prefix)
            self.assertIn("OUT OF BAND", line, prefix)  # base tier untouched
            for marker in tool_markers:
                self.assertNotIn(marker, line, f"{prefix} claims {marker}")

    def test_section7_upgraded_by_bucket_exposure(self):
        line = row_line(self.render({"bucket_exposure"}), "7.")
        self.assertIn("PARTIAL", line)
        self.assertIn("bucket_exposure", line)
        self.assertIn("scope-guarded", line)
        self.assertNotIn("cloud_posture_report", line)

    def test_section7_report_parse_admits_no_recheck(self):
        line = row_line(self.render({"cloud_posture_report"}), "7.")
        self.assertIn("cloud_posture_report", line)
        self.assertIn("NOT re-checked", line)
        self.assertNotIn("bucket_exposure", line)

    def test_section14_upgrade_lists_what_ran(self):
        line = row_line(
            self.render({"manifest_audit", "apk_badging",
                         "decompile_secrets"}), "14.")
        self.assertIn("PARTIAL", line)
        self.assertIn("manifest_audit", line)
        self.assertIn("apk_badging", line)
        self.assertIn("decompile_secrets", line)
        self.assertIn("need a device", line)

    def test_section15_partial_on_subset(self):
        line = row_line(self.render({"image_scan"}), "15.")
        self.assertIn("PARTIAL", line)
        self.assertIn("trivy image scan", line)
        self.assertNotIn("kube-linter", line)
        self.assertNotIn("kubeaudit", line)

    def test_section15_checked_on_full_battery(self):
        line = row_line(
            self.render({"image_scan", "kube_lint", "kube_audit"}), "15.")
        self.assertIn("CHECKED", line)
        self.assertIn("trivy image scan", line)
        self.assertIn("kube-linter", line)
        self.assertIn("kubeaudit", line)

    def test_section17_upgrade_never_promises_execution(self):
        line = row_line(self.render({"ad_collect", "ad_analyze"}), "17.")
        self.assertIn("PARTIAL", line)
        self.assertIn("passive bloodhound-python", line)
        self.assertIn("never executed", line)
        self.assertIn("exploitation stays manual", line)

    def test_section19_upgrade_names_the_battery(self):
        line = row_line(
            self.render({"ai_endpoint_probe", "prompt_probe"}), "19.")
        self.assertIn("PARTIAL", line)
        self.assertIn("ai_endpoint_probe", line)
        self.assertIn("prompt_probe", line)
        self.assertIn("direct override", line)
        self.assertIn("remain out of scope", line)


if __name__ == "__main__":
    unittest.main()
