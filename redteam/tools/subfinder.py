"""subfinder passive subdomain enumeration wrapper."""

from __future__ import annotations

from typing import Any

from .base import Tool, ToolError, ToolResult


class SubfinderTool(Tool):
    name = "subdomain_enum"
    description = (
        "Passive subdomain enumeration with subfinder for an authorized domain. "
        "Uses public sources only (no direct traffic to the target)."
    )
    binary = "subfinder"
    parameters = {
        "type": "object",
        "properties": {
            "domain": {"type": "string", "description": "Apex domain, e.g. example.com"},
        },
        "required": ["domain"],
    }

    def run(self, args: dict[str, Any]) -> ToolResult:
        domain = str(args["domain"]).strip().lower().lstrip("*.")
        cmd = ["subfinder", "-d", domain, "-silent", "-timeout", "30"]
        proc = self.shell(cmd, timeout=600)

        subs = sorted({line.strip().lower() for line in proc.stdout.splitlines() if line.strip()})
        if not subs and proc.returncode != 0:
            raise ToolError(f"subfinder failed (rc={proc.returncode}): {proc.stderr[:300]}")

        summary = f"subfinder found {len(subs)} subdomain(s) for {domain}"
        return ToolResult(ok=True, summary=summary, data={"subdomains": subs}, raw="\n".join(subs))
