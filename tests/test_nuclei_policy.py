"""Phase 1.2: nuclei scan policy — severity floor, tag universe, hard DoS
ban, template pinning. All offline: command building is pure, pin checks use
a throwaway local git repo, and the tool is tested with a stubbed shell."""

from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import yaml

from redteam.config import NucleiConfig, load_config
from redteam.tools.base import ToolError
from redteam.tools.nuclei import (
    HARD_EXCLUDED_TAGS,
    NucleiTool,
    build_nuclei_args,
    clamp_severity,
    curate_tags,
    resolve_template_pin,
)


def make_git_repo() -> tuple[Path, str]:
    d = Path(tempfile.mkdtemp()) / "tpl"
    d.mkdir()
    subprocess.run(["git", "init", "-q", str(d)], check=True, capture_output=True)
    subprocess.run(
        ["git", "-C", str(d), "-c", "user.email=t@t", "-c", "user.name=t",
         "commit", "-q", "--allow-empty", "-m", "pin"],
        check=True, capture_output=True,
    )
    head = subprocess.run(
        ["git", "-C", str(d), "rev-parse", "HEAD"],
        capture_output=True, text=True, check=True,
    ).stdout.strip()
    return d, head


class TestSeverityFloor(unittest.TestCase):
    def test_no_request_scans_from_floor_up(self):
        self.assertEqual(clamp_severity(None, "medium"), "critical,high,medium")
        self.assertEqual(clamp_severity("", "info"),
                         "critical,high,medium,low,info")

    def test_request_above_floor_kept(self):
        self.assertEqual(clamp_severity("critical,high", "medium"),
                         "critical,high")

    def test_mixed_request_keeps_only_at_or_above_floor(self):
        self.assertEqual(clamp_severity("low,critical", "medium"), "critical")

    def test_request_entirely_below_floor_fails_loudly(self):
        with self.assertRaises(ToolError) as cm:
            clamp_severity("low,info", "medium")
        self.assertIn("below the configured floor", str(cm.exception))

    def test_unknown_severity_rejected(self):
        with self.assertRaises(ToolError):
            clamp_severity("nope", "info")


class TestTagPolicy(unittest.TestCase):
    def setUp(self):
        self.cfg = NucleiConfig()  # default exclude: dos, fuzz

    def test_dos_dropped_and_reported(self):
        effective, dropped = curate_tags("cve,xss,dos", self.cfg)
        self.assertEqual(effective, ["cve", "xss"])
        self.assertEqual(dropped, ["dos"])

    def test_hard_ban_beats_include_universe(self):
        # operator put 'dos' in the allow universe — hard policy still wins
        cfg = NucleiConfig(tags_include=["dos", "cve"], tags_exclude=[])
        effective, dropped = curate_tags("dos,cve", cfg)
        self.assertEqual(effective, ["cve"])
        self.assertEqual(dropped, ["dos"])
        self.assertIn("dos", HARD_EXCLUDED_TAGS)

    def test_universe_filters_unknown_tags(self):
        cfg = NucleiConfig(tags_include=["cve", "apache"])
        effective, dropped = curate_tags("cve,nginx", cfg)
        self.assertEqual(effective, ["cve"])
        self.assertEqual(dropped, ["nginx"])

    def test_duplicates_removed(self):
        self.assertEqual(curate_tags("cve,cve,xss", self.cfg),
                         (["cve", "xss"], []))

    def test_empty_request_passes_through(self):
        self.assertEqual(curate_tags("", self.cfg), ([], []))
        self.assertEqual(curate_tags(None, self.cfg), ([], []))


class TestArgBuilding(unittest.TestCase):
    def test_update_check_always_disabled(self):
        cmd = build_nuclei_args("https://t", NucleiConfig(), "high", [], None)
        self.assertIn("-duc", cmd)

    def test_excludes_always_passed_even_without_tags(self):
        cmd = build_nuclei_args("https://t", NucleiConfig(), "info", [], None)
        i = cmd.index("-exclude-tags")
        self.assertEqual(set(cmd[i + 1].split(",")), {"dos", "fuzz"})

    def test_url_vs_host_flags(self):
        self.assertIn("-u", build_nuclei_args("https://t", NucleiConfig(),
                                              "high", [], None))
        self.assertIn("-target", build_nuclei_args("host.tld", NucleiConfig(),
                                                   "high", [], None))

    def test_severity_tags_template_dir_present(self):
        cmd = build_nuclei_args("https://t", NucleiConfig(), "critical,high",
                                ["cve", "xss"], "/tmp/tpl")
        self.assertEqual(cmd[cmd.index("-severity") + 1], "critical,high")
        self.assertEqual(cmd[cmd.index("-tags") + 1], "cve,xss")
        self.assertEqual(cmd[cmd.index("-t") + 1], "/tmp/tpl")


class TestTemplatePin(unittest.TestCase):
    def test_no_template_dir_is_flagged_unpinned(self):
        path, note = resolve_template_pin(NucleiConfig())
        self.assertIsNone(path)
        self.assertIn("UNPINNED", note)

    def test_missing_dir_raises(self):
        with self.assertRaises(ToolError):
            resolve_template_pin(NucleiConfig(template_dir="/nonexistent/tpl",
                                              expected_commit="abc"))

    def test_matching_pin_accepted(self):
        d, head = make_git_repo()
        path, note = resolve_template_pin(
            NucleiConfig(template_dir=str(d), expected_commit=head))
        self.assertEqual(path, str(d))
        self.assertIn(head[:12], note)

    def test_abbreviated_pin_accepted(self):
        d, head = make_git_repo()
        _, note = resolve_template_pin(
            NucleiConfig(template_dir=str(d), expected_commit=head[:8]))
        self.assertIn(head[:12], note)

    def test_mismatched_pin_refuses_to_scan(self):
        d, head = make_git_repo()
        with self.assertRaises(ToolError) as cm:
            resolve_template_pin(NucleiConfig(template_dir=str(d),
                                              expected_commit="0" * 40))
        self.assertIn("pin mismatch", str(cm.exception))

    def test_expected_commit_without_git_checkout_refuses(self):
        d = Path(tempfile.mkdtemp())
        with self.assertRaises(ToolError) as cm:
            resolve_template_pin(NucleiConfig(template_dir=str(d),
                                              expected_commit="abc"))
        self.assertIn("not a git checkout", str(cm.exception))

    def test_dir_without_expected_commit_runs_unenforced(self):
        d = Path(tempfile.mkdtemp())
        path, note = resolve_template_pin(NucleiConfig(template_dir=str(d)))
        self.assertEqual(path, str(d))
        self.assertIn("pin not enforced", note)


class TestToolEnforcement(unittest.TestCase):
    """The tool (not just the helpers) enforces the policy end to end."""

    def _run_tool(self, args, cfg):
        captured: dict = {}

        def fake_shell(cmd, timeout=600, stdin=None):
            captured["cmd"] = cmd
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

        tool = NucleiTool(cfg)
        with mock.patch.object(tool, "shell", side_effect=fake_shell):
            return tool.run(args), captured["cmd"]

    def test_policy_reported_in_empty_result(self):
        result, _ = self._run_tool({"target": "https://t"}, NucleiConfig())
        self.assertTrue(result.ok)
        self.assertEqual(result.data["policy"]["dropped_tags"], [])
        self.assertIn("UNPINNED", result.data["policy"]["template_pin"])

    def test_all_tags_dropped_fails_instead_of_scanning_broad(self):
        tool = NucleiTool(NucleiConfig())
        with self.assertRaises(ToolError) as cm:
            tool.run({"target": "https://t", "tags": "dos,fuzz"})
        self.assertIn("dropped by policy", str(cm.exception))

    def test_dropped_tags_surface_in_summary(self):
        def fake_shell(cmd, timeout=600, stdin=None):
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

        tool = NucleiTool(NucleiConfig())
        with mock.patch.object(tool, "shell", side_effect=fake_shell):
            result = tool.run({"target": "https://t", "tags": "cve,dos"})
        self.assertIn("policy dropped tags: dos", result.summary)

    def test_below_floor_request_never_reaches_shell(self):
        tool = NucleiTool(NucleiConfig(severity_floor="high"))
        with mock.patch.object(tool, "shell") as shell:
            with self.assertRaises(ToolError):
                tool.run({"target": "https://t", "severity": "low,info"})
            shell.assert_not_called()


class TestConfigParsing(unittest.TestCase):
    def _load(self, nuclei_section: str, safety_extra: str = ""):
        raw = {
            "llm": {
                "hosted": {"provider": "openai_compatible",
                           "base_url": "https://api.example.com/v1",
                           "api_key_env": "K", "model": "m"},
                "local": {"provider": "openai_compatible",
                          "base_url": "http://localhost:11434/v1",
                          "api_key_env": "O", "model": "m"},
            },
            "scope": {"allow_domains": ["localhost"]},
            "safety": {"artifacts_dir": tempfile.mkdtemp()},
            "nuclei": yaml.safe_load(nuclei_section) if nuclei_section else {},
        }
        p = Path(tempfile.mkdtemp()) / "cfg.yaml"
        p.write_text(yaml.safe_dump(raw), encoding="utf-8")
        return load_config(p)

    def test_nuclei_section_parsed(self):
        cfg = self._load(
            "severity_floor: medium\n"
            "tags_include: [cve, apache]\n"
            "tags_exclude: [dos]\n"
            "template_dir: ./tpl\n"
            "expected_commit: abc123\n"
        )
        self.assertEqual(cfg.nuclei.severity_floor, "medium")
        self.assertEqual(cfg.nuclei.tags_include, ["cve", "apache"])
        self.assertEqual(cfg.nuclei.tags_exclude, ["dos"])
        self.assertEqual(cfg.nuclei.template_dir, "./tpl")
        self.assertEqual(cfg.nuclei.expected_commit, "abc123")
        self.assertEqual(cfg.nuclei.update_policy, "manual")

    def test_defaults_when_section_missing(self):
        cfg = self._load("")
        self.assertEqual(cfg.nuclei.severity_floor, "info")
        self.assertIn("dos", cfg.nuclei.tags_exclude)
        self.assertEqual(cfg.nuclei.update_policy, "manual")

    def test_invalid_floor_rejected(self):
        with self.assertRaises(ValueError):
            self._load("severity_floor: apocalyptic\n")

    def test_auto_update_policy_rejected(self):
        with self.assertRaises(ValueError) as cm:
            self._load("update_policy: auto\n")
        self.assertIn("manual", str(cm.exception))

    def test_checks_dir_parsed(self):
        raw = {
            "llm": {
                "hosted": {"provider": "openai_compatible",
                           "base_url": "https://api.example.com/v1",
                           "api_key_env": "K", "model": "m"},
                "local": {"provider": "openai_compatible",
                          "base_url": "http://localhost:11434/v1",
                          "api_key_env": "O", "model": "m"},
            },
            "scope": {"allow_domains": ["localhost"]},
            "safety": {"artifacts_dir": tempfile.mkdtemp(),
                       "checks_dir": "./mychecks"},
        }
        p = Path(tempfile.mkdtemp()) / "cfg.yaml"
        p.write_text(yaml.safe_dump(raw), encoding="utf-8")
        self.assertEqual(load_config(p).safety.checks_dir, "./mychecks")


if __name__ == "__main__":
    unittest.main()
