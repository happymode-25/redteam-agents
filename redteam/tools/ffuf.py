"""ffuf content-discovery wrapper with a built-in small wordlist.

Rate-limited by default. The wordlist is intentionally small (~120 entries)
to keep runs fast and noisy-free; point `wordlist` at a seclists path for
deeper discovery when authorized.
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Any

from .base import Tool, ToolError, ToolResult

BUILTIN_WORDLIST = Path(__file__).resolve().parents[2] / "wordlists" / "common-paths.txt"
DEFAULT_STATUSES = "200,204,301,302,307,401,403,500"


def parse_ffuf_json(text: str) -> list[dict]:
    try:
        doc = json.loads(text)
    except json.JSONDecodeError:
        # tolerate newline-delimited fallback
        results = []
        for line in text.splitlines():
            line = line.strip()
            if line.startswith("{"):
                try:
                    results.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        return results
    if isinstance(doc, dict):
        results = doc.get("results") or []
    elif isinstance(doc, list):
        results = doc
    else:
        results = []
    out = []
    for r in results:
        if not isinstance(r, dict):
            continue
        out.append({
            "url": r.get("url"),
            "status": r.get("status"),
            "length": r.get("length"),
            "words": r.get("words"),
            "fuzz": (r.get("input") or {}).get("FUZZ"),
        })
    return out


class ContentDiscoveryTool(Tool):
    name = "content_discovery"
    description = (
        "Discover hidden paths/endpoints on an authorized origin with ffuf "
        "using a small built-in wordlist (admin panels, backups, config leaks, "
        "API roots). Rate-limited; use it after web_probe on each live origin."
    )
    binary = "ffuf"
    parameters = {
        "type": "object",
        "properties": {
            "base_url": {
                "type": "string",
                "description": "Origin URL, e.g. https://example.com (must be in scope)",
            },
            "extensions": {
                "type": "string",
                "description": "Optional comma-separated extensions, e.g. 'php,bak'",
            },
            "rate": {
                "type": "integer",
                "description": "Requests per second, default 20 (max 100)",
            },
            "wordlist": {
                "type": "string",
                "description": "Optional path to a custom wordlist (one path per line)",
            },
        },
        "required": ["base_url"],
    }

    def run(self, args: dict[str, Any]) -> ToolResult:
        base_url = str(args["base_url"]).rstrip("/")
        wordlist = Path(args["wordlist"]) if args.get("wordlist") else BUILTIN_WORDLIST
        if not wordlist.exists():
            raise ToolError(f"wordlist not found: {wordlist}")
        rate = max(1, min(int(args.get("rate") or 20), 100))

        cmd = [
            "ffuf",
            "-u", f"{base_url}/FUZZ",
            "-w", f"{wordlist}:FUZZ",
            "-mc", DEFAULT_STATUSES,
            "-t", "10",
            "-rate", str(rate),
            "-timeout", "10",
            "-noninteractive",
            "-s",
        ]
        if args.get("extensions"):
            cmd += ["-e", str(args["extensions"])]

        with tempfile.NamedTemporaryFile(
            mode="r", suffix=".json", delete=False, encoding="utf-8"
        ) as tmp:
            out_path = Path(tmp.name)
        try:
            cmd += ["-of", "json", "-o", str(out_path)]
            proc = self.shell(cmd, timeout=1800)
            output = out_path.read_text(encoding="utf-8") if out_path.exists() else ""
        finally:
            out_path.unlink(missing_ok=True)

        results = parse_ffuf_json(output)
        if not results and proc.returncode not in (0,):
            raise ToolError(f"ffuf failed (rc={proc.returncode}): {proc.stderr[:300]}")

        results.sort(key=lambda r: -(r.get("length") or 0))
        summary = f"ffuf found {len(results)} responding path(s) on {base_url}"
        return ToolResult(ok=True, summary=summary,
                          data={"matches": results[:100]}, raw=output[:100_000])
