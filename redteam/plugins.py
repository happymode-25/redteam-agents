"""Custom check plugin format (Phase 1.2).

A check is one Python file in the checks directory containing:

    MANIFEST = {
        "id": "my_check",                 # [a-z][a-z0-9_]{2,39}, unique
        "title": "Human title",
        "catalog_section": 12,            # 1..28 index into redteam.coverage
        "description": "What the agent should know before calling it",
        "parameters": { ...JSON schema, "type": "object"... },
        "severity_default": "medium",     # critical|high|medium|low|info
        "prereqs": ["in-scope https origin"],   # optional, informational
        "requires_active": False,         # optional; True = needs --allow-active
    }

    def run(ctx):                          # ctx: PluginContext
        resp = ctx.session.get(...)        # ScopedSession: scope + pinning apply
        return {"summary": "...", "findings": [...]}

TRUST MODEL (be honest about it): plugins are OPERATOR-INSTALLED local code.
Review them like any dependency — they run in-process with full Python. The
LLM does not write or modify them; it only chooses when to call one and
passes arguments matching the manifest schema. Network access still goes
through the injected ScopedSession, so the ScopeGuard applies to plugin
traffic, and ScopeViolation aborts the stage (it is never swallowed).
"""

from __future__ import annotations

import importlib.util
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from .coverage import CATALOG
from .http import ScopedSession
from .scope import Guard, ScopeViolation
from .tools.base import Tool, ToolError, ToolResult

SEVERITIES = ("critical", "high", "medium", "low", "info")
ID_RE = re.compile(r"^[a-z][a-z0-9_]{2,39}$")
REQUIRED_KEYS = ("id", "title", "catalog_section", "description",
                 "parameters", "severity_default")
MAX_PLUGIN_OUTPUT_CHARS = 20_000


class PluginLoadError(Exception):
    """A plugin file is malformed; loader skips it and records a warning."""


@dataclass(frozen=True)
class PluginManifest:
    id: str
    title: str
    catalog_section: int
    description: str
    parameters: dict[str, Any]
    severity_default: str
    prereqs: tuple[str, ...] = ()
    requires_active: bool = False

    @property
    def section_title(self) -> str:
        return CATALOG[self.catalog_section - 1].section


@dataclass
class Plugin:
    manifest: PluginManifest
    run: Callable[..., dict]
    source: str

    def execute(self, ctx: "PluginContext") -> dict:
        out = self.run(ctx)
        if not isinstance(out, dict):
            raise PluginLoadError(
                f"{self.manifest.id}: run() must return a dict, got {type(out).__name__}"
            )
        if "summary" not in out:
            out["summary"] = f"{self.manifest.id}: no summary provided"
        return out


def _validate_manifest(raw: Any, source: str) -> PluginManifest:
    if not isinstance(raw, dict):
        raise PluginLoadError(f"{source}: MANIFEST dict is missing or not a dict")
    missing = [k for k in REQUIRED_KEYS if k not in raw]
    if missing:
        raise PluginLoadError(f"{source}: MANIFEST missing keys {missing}")
    pid = str(raw["id"])
    if not ID_RE.match(pid):
        raise PluginLoadError(
            f"{source}: id {pid!r} must match {ID_RE.pattern}"
        )
    section = raw["catalog_section"]
    if not isinstance(section, int) or not (1 <= section <= len(CATALOG)):
        raise PluginLoadError(
            f"{source}: catalog_section must be an int 1..{len(CATALOG)}, got {section!r}"
        )
    severity = str(raw["severity_default"]).lower()
    if severity not in SEVERITIES:
        raise PluginLoadError(
            f"{source}: severity_default must be one of {list(SEVERITIES)}, got {severity!r}"
        )
    params = raw["parameters"]
    if not isinstance(params, dict) or params.get("type") != "object" \
       or not isinstance(params.get("properties"), dict):
        raise PluginLoadError(
            f"{source}: parameters must be a JSON schema object with 'properties'"
        )
    return PluginManifest(
        id=pid,
        title=str(raw["title"]),
        catalog_section=section,
        description=str(raw["description"]),
        parameters=params,
        severity_default=severity,
        prereqs=tuple(str(p) for p in raw.get("prereqs", ())),
        requires_active=bool(raw.get("requires_active", False)),
    )


def load_plugin(path: Path) -> Plugin:
    module_name = f"redteam_checks_{path.stem}"
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:
        raise PluginLoadError(f"{path.name}: cannot create import spec")
    module = importlib.util.module_from_spec(spec)
    try:
        sys.modules[module_name] = module
        spec.loader.exec_module(module)
    except Exception as exc:
        sys.modules.pop(module_name, None)
        raise PluginLoadError(
            f"{path.name}: import failed: {type(exc).__name__}: {exc}"
        ) from exc
    manifest = _validate_manifest(getattr(module, "MANIFEST", None), path.name)
    run = getattr(module, "run", None)
    if not callable(run):
        raise PluginLoadError(f"{path.name}: missing run(ctx) function")
    return Plugin(manifest=manifest, run=run, source=str(path))


def load_plugins(checks_dir: Path) -> tuple[list[Plugin], list[str]]:
    """Load every *.py check (skipping _underscore files).

    Returns (plugins, warnings). Malformed plugins are skipped with a
    warning — a broken check never blocks the run.
    """
    checks_dir = Path(checks_dir)
    if not checks_dir.is_dir():
        return [], [f"checks directory not found: {checks_dir}"]
    plugins: list[Plugin] = []
    warnings: list[str] = []
    seen_ids: dict[str, str] = {}
    for path in sorted(checks_dir.glob("*.py")):
        if path.name.startswith("_"):
            continue
        try:
            plugin = load_plugin(path)
        except PluginLoadError as exc:
            warnings.append(f"skipped {path.name}: {exc}")
            continue
        if plugin.manifest.id in seen_ids:
            warnings.append(
                f"skipped {path.name}: duplicate id '{plugin.manifest.id}' "
                f"(already defined in {seen_ids[plugin.manifest.id]})"
            )
            continue
        seen_ids[plugin.manifest.id] = path.name
        plugins.append(plugin)
    return plugins, warnings


@dataclass
class PluginContext:
    """Everything a plugin may touch: its arguments, a scoped HTTP session,
    and the guard. Nothing else is provided."""

    args: dict[str, Any]
    session: ScopedSession
    guard: Guard


class PluginTool(Tool):
    """Wraps a loaded plugin so agents see it like any built-in tool."""

    binary = None

    def __init__(self, plugin: Plugin, guard: Guard, allow_active: bool = False):
        self.plugin = plugin
        self.guard = guard
        self.allow_active = allow_active
        m = plugin.manifest
        self.name = m.id
        self.description = (
            f"[custom check · §{m.catalog_section} {m.section_title}] "
            f"{m.title}: {m.description}"
            + (f" Requires the active stage (--allow-active)." if m.requires_active else "")
        )
        self.parameters = m.parameters

    def run(self, args: dict[str, Any]) -> ToolResult:
        m = self.plugin.manifest
        if m.requires_active and not self.allow_active:
            raise ToolError(
                f"plugin {m.id} requires the active stage — rerun with --allow-active"
            )
        ctx = PluginContext(
            args=args,
            session=ScopedSession(self.guard, timeout=15, max_redirects=3),
            guard=self.guard,
        )
        try:
            result = self.plugin.execute(ctx)
        except ScopeViolation:
            raise  # scope aborts the stage; never degrade to a tool error
        except ToolError:
            raise
        except Exception as exc:
            raise ToolError(
                f"plugin {m.id} failed: {type(exc).__name__}: {exc}"
            ) from exc

        summary = str(result.pop("summary", m.id))
        try:
            payload = json.dumps(result, ensure_ascii=False, default=str)
        except (TypeError, ValueError) as exc:
            raise ToolError(f"{m.id}: run() returned non-JSON-able data: {exc}") from exc
        if len(payload) > MAX_PLUGIN_OUTPUT_CHARS:
            return ToolResult(
                ok=True,
                summary=f"{summary} [output truncated by plugin I/O limit "
                        f"({len(payload)} > {MAX_PLUGIN_OUTPUT_CHARS} chars)]",
                data={"truncated": True,
                      "note": "plugin output exceeded MAX_PLUGIN_OUTPUT_CHARS; "
                              "reduce result size in the check",
                      "chars": len(payload)},
            )
        return ToolResult(ok=True, summary=summary, data=result, raw=payload)
