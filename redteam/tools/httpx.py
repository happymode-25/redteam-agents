"""httpx web probe wrapper (ProjectDiscovery httpx)."""

from __future__ import annotations

import json
from typing import Any

from .base import Tool, ToolError, ToolResult


class HttpxTool(Tool):
    name = "web_probe"
    description = (
        "Probe web targets with httpx: HTTP status, page title, tech detection, "
        "web server and redirect chain. Takes a list of URLs or hostnames."
    )
    binary = "httpx"
    parameters = {
        "type": "object",
        "properties": {
            "targets": {
                "type": "array",
                "items": {"type": "string"},
                "description": "URLs or hostnames to probe (all must be in scope)",
            },
        },
        "required": ["targets"],
    }

    def run(self, args: dict[str, Any]) -> ToolResult:
        targets = [str(t).strip() for t in (args.get("targets") or []) if str(t).strip()]
        if not targets:
            raise ToolError("web_probe requires at least one target")

        stdin = "\n".join(targets) + "\n"
        cmd = [
            "httpx",
            "-json",
            "-status-code",
            "-title",
            "-tech-detect",
            "-web-server",
            "-silent",
            "-timeout", "10",
            "-retries", "1",
            "-threads", "10",
        ]
        proc = self.shell(cmd, timeout=900, stdin=stdin)

        results: list[dict[str, Any]] = []
        for line in proc.stdout.splitlines():
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            results.append(
                {
                    "url": rec.get("url"),
                    "status_code": rec.get("status_code"),
                    "title": (rec.get("title") or "").strip()[:200],
                    "webserver": rec.get("webserver"),
                    "tech": [str(t)[:80] for t in (rec.get("tech") or [])[:15]],
                    "final_url": rec.get("final_url"),
                }
            )

        if not results and proc.returncode not in (0,):
            raise ToolError(f"httpx failed (rc={proc.returncode}): {proc.stderr[:300]}")

        summary = f"probed {len(results)} live web endpoint(s)"
        return ToolResult(ok=True, summary=summary, data={"endpoints": results}, raw=proc.stdout)
