"""Tool abstraction: every external capability is a Tool with a JSON schema
the LLM can see and a guarded run() the orchestrator executes."""

from __future__ import annotations

import json
import shutil
import subprocess
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


class LocalRunner:
    """Default subprocess runner: executes tools directly on the host."""

    def run(self, cmd: list[str], timeout: int = 600,
            stdin: str | None = None) -> subprocess.CompletedProcess:
        try:
            return subprocess.run(
                cmd,
                input=stdin,
                capture_output=True,
                text=True,
                timeout=timeout,
                encoding="utf-8",
                errors="replace",
            )
        except subprocess.TimeoutExpired as exc:
            raise ToolError(f"command timed out after {timeout}s: {' '.join(cmd)}") from exc


_runner: Any = LocalRunner()


def set_runner(runner: Any) -> None:
    """Swap the subprocess runner (e.g. DockerRunner from sandbox.py)."""
    global _runner
    _runner = runner


@dataclass
class ToolResult:
    ok: bool
    summary: str
    data: dict[str, Any] = field(default_factory=dict)
    raw: str = ""

    def to_observation(self, max_chars: int = 6000) -> str:
        text = self.summary
        if self.data:
            text += "\n" + json.dumps(self.data, indent=2, ensure_ascii=False)
        if len(text) > max_chars:
            text = text[:max_chars] + "\n...[observation truncated]"
        return text


class ToolError(Exception):
    pass


class Tool(ABC):
    name: str = ""
    description: str = ""
    parameters: dict[str, Any] = {}  # JSON schema, object type
    binary: str | None = None  # required CLI binary, checked on PATH

    def available(self) -> tuple[bool, str]:
        if self.binary and not shutil.which(self.binary):
            return False, f"`{self.binary}` not found on PATH"
        return True, ""

    @abstractmethod
    def run(self, args: dict[str, Any]) -> ToolResult:
        ...

    @staticmethod
    def shell(
        cmd: list[str], timeout: int = 600, stdin: str | None = None
    ) -> subprocess.CompletedProcess:
        return _runner.run(cmd, timeout=timeout, stdin=stdin)


class ToolRegistry:
    def __init__(self, tools: list[Tool]):
        self._tools = {t.name: t for t in tools}

    def get(self, name: str) -> Tool | None:
        return self._tools.get(name)

    def available_tools(self) -> list[Tool]:
        return [t for t in self._tools.values() if t.available()[0]]

    def schemas(self) -> list[dict[str, Any]]:
        return [
            {"name": t.name, "description": t.description, "parameters": t.parameters}
            for t in self.available_tools()
        ]
