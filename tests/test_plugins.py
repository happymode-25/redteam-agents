"""Phase 1.2: custom check plugin format — loader validation, PluginTool
behavior (I/O cap, active gating, scope abort), and orchestrator wiring."""

from __future__ import annotations

import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from redteam.config import load_config
from redteam.coverage import CATALOG
from redteam.plugins import (
    MAX_PLUGIN_OUTPUT_CHARS,
    PluginTool,
    load_plugin,
    load_plugins,
)
from redteam.scope import ScopeViolation
from redteam.tools.base import ToolError

from test_phase1 import make_guard

VALID_PLUGIN = '''\
MANIFEST = {
    "id": "sample_check",
    "title": "Sample check",
    "catalog_section": 1,
    "description": "A sample custom check used by the tests.",
    "parameters": {"type": "object",
                   "properties": {"url": {"type": "string"}},
                   "required": ["url"]},
    "severity_default": "low",
}

def run(ctx):
    return {"summary": "sample ran", "findings": [{"severity": "low"}],
            "echo": ctx.args}
'''

VALID_DIR = "2"   # "2. Authentication and Session"


def write_plugin(directory: Path, name: str, content: str) -> Path:
    p = directory / name
    p.write_text(content, encoding="utf-8")
    return p


def make_checks_dir(*files: tuple[str, str]) -> Path:
    d = Path(tempfile.mkdtemp()) / "checks"
    d.mkdir()
    for name, content in files:
        write_plugin(d, name, content)
    return d


def plugin_with(manifest_overrides: str, run_body: str = "pass") -> str:
    return (
        "MANIFEST = {\n"
        '    "id": "x_check",\n'
        '    "title": "t",\n'
        '    "catalog_section": 1,\n'
        '    "description": "d",\n'
        '    "parameters": {"type": "object", "properties": {}},\n'
        '    "severity_default": "low",\n'
        f"{manifest_overrides}\n"
        "}\n"
        f"def run(ctx):\n    {run_body}\n"
    )


class TestLoader(unittest.TestCase):
    def test_valid_plugin_loads(self):
        d = make_checks_dir(("sample.py", VALID_PLUGIN))
        plugins, warnings = load_plugins(d)
        self.assertEqual(warnings, [])
        self.assertEqual(len(plugins), 1)
        m = plugins[0].manifest
        self.assertEqual(m.id, "sample_check")
        self.assertEqual(m.catalog_section, 1)
        self.assertEqual(m.section_title, CATALOG[0].section)
        self.assertFalse(m.requires_active)

    def test_broken_plugins_skipped_with_warnings(self):
        d = make_checks_dir(
            ("no_manifest.py", "def run(ctx):\n    return {}\n"),
            ("bad_id.py", plugin_with('    "id": "Bad-Id!",', "return {}")),
            ("bad_section.py", plugin_with('    "catalog_section": 0,', "return {}")),
            ("huge_section.py", plugin_with('    "catalog_section": 99,', "return {}")),
            ("bad_severity.py", plugin_with('    "severity_default": "meh",',
                                            "return {}")),
            ("no_run.py", 'MANIFEST = {"id": "y_check", "title": "t",\n'
                          ' "catalog_section": 1, "description": "d",\n'
                          ' "parameters": {"type": "object", "properties": {}},\n'
                          ' "severity_default": "low"}\n'),
            ("syntax_error.py", "def run(:\n"),
            ("no_properties.py", plugin_with(
                '    "parameters": {"type": "object"},', "return {}")),
        )
        plugins, warnings = load_plugins(d)
        self.assertEqual(plugins, [])
        self.assertEqual(len(warnings), 8)
        for w in warnings:
            self.assertTrue(w.startswith("skipped "), w)

    def test_duplicate_ids_second_skipped(self):
        d = make_checks_dir(("a.py", VALID_PLUGIN), ("b.py", VALID_PLUGIN))
        plugins, warnings = load_plugins(d)
        self.assertEqual(len(plugins), 1)
        self.assertEqual(len(warnings), 1)
        self.assertIn("duplicate id", warnings[0])

    def test_underscore_files_ignored(self):
        d = make_checks_dir(("_helper.py", "not even valid python (("),
                            ("real.py", VALID_PLUGIN))
        plugins, warnings = load_plugins(d)
        self.assertEqual(len(plugins), 1)
        self.assertEqual(warnings, [])

    def test_missing_directory_is_a_warning_not_a_crash(self):
        plugins, warnings = load_plugins(Path(tempfile.mkdtemp()) / "nope")
        self.assertEqual(plugins, [])
        self.assertEqual(len(warnings), 1)
        self.assertIn("not found", warnings[0])

    def test_example_checks_in_repo_load_cleanly(self):
        root = Path(__file__).resolve().parent.parent / "checks"
        plugins, warnings = load_plugins(root)
        self.assertEqual(warnings, [])
        ids = {p.manifest.id for p in plugins}
        self.assertEqual(ids, {"exposed_vcs", "robots_recon"})


class TestPluginTool(unittest.TestCase):
    def setUp(self):
        self.guard = make_guard()

    def _tool(self, plugin_content: str, allow_active: bool = False) -> PluginTool:
        d = make_checks_dir(("p.py", plugin_content))
        return PluginTool(load_plugin(d / "p.py"), self.guard,
                          allow_active=allow_active)

    def test_success_returns_summary_and_data(self):
        tool = self._tool(VALID_PLUGIN)
        result = tool.run({"url": "https://x"})
        self.assertTrue(result.ok)
        self.assertEqual(result.summary, "sample ran")
        self.assertEqual(result.data["echo"], {"url": "https://x"})
        self.assertEqual(len(result.data["findings"]), 1)

    def test_description_names_catalog_section(self):
        tool = self._tool(VALID_PLUGIN)
        self.assertTrue(tool.description.startswith("[custom check · §1"))
        self.assertIn("Sample check", tool.description)

    def test_plugin_exception_becomes_tool_error(self):
        tool = self._tool(plugin_with("", "raise RuntimeError('boom')"))
        with self.assertRaises(ToolError) as cm:
            tool.run({})
        self.assertIn("x_check", str(cm.exception))
        self.assertIn("boom", str(cm.exception))

    def test_non_dict_return_is_a_tool_error(self):
        tool = self._tool(plugin_with("", "'just a string'"))
        with self.assertRaises(ToolError):
            tool.run({})

    def test_oversized_output_truncated_with_flag(self):
        tool = self._tool(plugin_with(
            "", f'return {{"summary": "big", "blob": "x" * {MAX_PLUGIN_OUTPUT_CHARS + 1}}}'))
        result = tool.run({})
        self.assertTrue(result.data["truncated"])
        self.assertIn("truncated", result.summary)

    def test_requires_active_refuses_without_flag(self):
        content = plugin_with('    "requires_active": True,',
                              'return {"summary": "ran"}')
        tool = self._tool(content, allow_active=False)
        with self.assertRaises(ToolError) as cm:
            tool.run({})
        self.assertIn("--allow-active", str(cm.exception))
        tool_open = self._tool(content, allow_active=True)
        self.assertEqual(tool_open.run({}).summary, "ran")

    def test_scope_violation_aborts_not_degrades(self):
        tool = self._tool(plugin_with(
            "",
            'ctx.session.get("https://evil.invalid/leak")\n    return {}'))
        with self.assertRaises(ScopeViolation):
            tool.run({})


class TestOrchestratorWiring(unittest.TestCase):
    def _orch(self, checks_dir: Path):
        from redteam.orchestrator import Orchestrator

        root = Path(__file__).resolve().parent.parent
        cfg = load_config(root / "config.example.yaml")
        tmp = Path(tempfile.mkdtemp())
        cfg = replace(cfg, safety=replace(
            cfg.safety,
            artifacts_dir=str(tmp / "art"),
            cassette_dir=str(tmp / "cass"),
            runner="local",
            checks_dir=str(checks_dir),
        ))
        return Orchestrator(cfg)

    def test_plugins_registered_as_tools(self):
        from redteam.tools.base import Tool
        from redteam.plugins import PluginTool as PT

        orch = self._orch(make_checks_dir(("sample.py", VALID_PLUGIN)))
        tool = orch.registry.get("sample_check")
        self.assertIsNotNone(tool)
        inner = getattr(tool, "inner", tool)
        self.assertIsInstance(inner, PT)

    def test_builtin_shadowing_refused(self):
        from redteam.tools.nuclei import NucleiTool

        orch = self._orch(make_checks_dir(
            ("nuclei_scan.py", VALID_PLUGIN.replace("sample_check",
                                                    "nuclei_scan"))))
        tool = orch.registry.get("nuclei_scan")
        inner = getattr(tool, "inner", tool)
        self.assertIsInstance(inner, NucleiTool)


if __name__ == "__main__":
    unittest.main()
