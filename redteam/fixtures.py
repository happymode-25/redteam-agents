"""Record/replay cassettes for tools and LLM calls (eval harness support).

Modes:
  live   — wrappers pass through and only count calls (default)
  record — pass through AND store every tool result / LLM response to disk
  replay — return stored results; never touch the network or an API.
           Misses return deterministic fallbacks so CI can't hang.

Cassette keys are SHA-1 digests of canonical (tool, args) / (model, system,
messages) payloads, so replay is exact-input keyed.
"""

from __future__ import annotations

import hashlib
import json
import threading
from pathlib import Path
from typing import Any

from .llm import Provider
from .tools.base import Tool, ToolResult

REPLAY_LLM_MISS = json.dumps(
    {"action": "final", "answer": "FIXTURE MISS: no recorded LLM response for this input."}
)
RAW_CAP = 200_000  # cap stored raw tool output per cassette entry


def _digest(payload: dict) -> str:
    canonical = json.dumps(payload, sort_keys=True, ensure_ascii=False)
    return hashlib.sha1(canonical.encode("utf-8")).hexdigest()


class FixtureManager:
    def __init__(self, directory: str | Path, mode: str = "live"):
        if mode not in ("live", "record", "replay"):
            raise ValueError(f"unknown fixture mode: {mode}")
        self.mode = mode
        self.dir = Path(directory)
        self._lock = threading.Lock()
        self.tools: dict[str, Any] = self._load("tools.json") if mode == "replay" else {}
        self.llm: dict[str, Any] = self._load("llm.json") if mode == "replay" else {}
        self.counts = {"llm_calls": 0, "tool_calls": 0, "fixture_hits": 0, "fixture_misses": 0}

    def _load(self, name: str) -> dict:
        path = self.dir / name
        if path.exists():
            try:
                return json.loads(path.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                return {}
        return {}

    def save(self) -> None:
        if self.mode != "record":
            return
        self.dir.mkdir(parents=True, exist_ok=True)
        with self._lock:
            (self.dir / "tools.json").write_text(
                json.dumps(self.tools, ensure_ascii=False), encoding="utf-8")
            (self.dir / "llm.json").write_text(
                json.dumps(self.llm, ensure_ascii=False), encoding="utf-8")

    # --- tools ---------------------------------------------------------------
    def tool_key(self, tool: str, args: dict) -> str:
        return _digest({"tool": tool, "args": args})

    def get_tool(self, key: str) -> dict | None:
        if self.mode != "replay":
            return None
        return self.tools.get(key)

    def put_tool(self, key: str, result: ToolResult) -> None:
        if self.mode != "record":
            return
        with self._lock:
            self.tools[key] = {
                "ok": result.ok,
                "summary": result.summary,
                "data": result.data,
                "raw": result.raw[:RAW_CAP],
            }

    # --- llm -----------------------------------------------------------------
    def llm_key(self, model: str, system: str, messages: list[dict]) -> str:
        return _digest({"model": model, "system": system, "messages": messages})

    def get_llm(self, key: str) -> dict | None:
        if self.mode != "replay":
            return None
        return self.llm.get(key)

    def put_llm(self, key: str, text: str) -> None:
        if self.mode != "record":
            return
        with self._lock:
            self.llm[key] = {"text": text}


class FixtureTool(Tool):
    """Wraps a tool with record/replay + call counting."""

    def __init__(self, inner: Tool, fx: FixtureManager):
        self.inner = inner
        self.fx = fx
        self.name = inner.name
        self.description = inner.description
        self.parameters = inner.parameters
        self.binary = inner.binary

    def available(self) -> tuple[bool, str]:
        return self.inner.available()

    def run(self, args: dict[str, Any]) -> ToolResult:
        with self.fx._lock:
            self.fx.counts["tool_calls"] += 1
        key = self.fx.tool_key(self.name, args)
        hit = self.fx.get_tool(key)
        if hit is not None:
            with self.fx._lock:
                self.fx.counts["fixture_hits"] += 1
            return ToolResult(
                ok=bool(hit.get("ok", False)),
                summary=str(hit.get("summary", "")),
                data=hit.get("data", {}),
                raw=str(hit.get("raw", "")),
            )
        if self.fx.mode == "replay":
            # Offline is a hard guarantee: never execute the real tool on a miss.
            with self.fx._lock:
                self.fx.counts["fixture_misses"] += 1
            return ToolResult(
                ok=False,
                summary=f"FIXTURE MISS: no recorded result for {self.name} "
                        f"with these args; re-record the cassette",
            )
        result = self.inner.run(args)
        self.fx.put_tool(key, result)
        return result


class FixtureProvider(Provider):
    """Wraps an LLM provider with record/replay + call counting."""

    def __init__(self, inner: Provider, fx: FixtureManager):
        self.inner = inner
        self.fx = fx
        self.model = inner.model

    def complete(self, system: str, messages: list[dict]) -> str:
        with self.fx._lock:
            self.fx.counts["llm_calls"] += 1
        key = self.fx.llm_key(self.model, system, messages)
        hit = self.fx.get_llm(key)
        if hit is not None:
            with self.fx._lock:
                self.fx.counts["fixture_hits"] += 1
            return str(hit.get("text", ""))
        if self.fx.mode == "replay":
            with self.fx._lock:
                self.fx.counts["fixture_misses"] += 1
            return REPLAY_LLM_MISS
        text = self.inner.complete(system, messages)
        self.fx.put_llm(key, text)
        return text
