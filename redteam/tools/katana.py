"""Katana crawler wrapper (Phase 1 discovery).

Post-filters every discovered URL through the scope guard: out-of-scope
findings are dropped (and counted) before any other agent or tool sees
them. The crawl itself runs with `-fs domain` so katana stays on the
target domain during discovery; post-filtering is the second layer.
"""

from __future__ import annotations

import json
from typing import Any
from urllib.parse import urlparse

from ..scope import Guard, ScopeViolation
from .base import Tool, ToolError, ToolResult


def parse_katana_jsonl(text: str) -> list[str]:
    urls: list[str] = []
    for line in text.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        url = rec.get("url")
        if isinstance(url, str) and url.startswith(("http://", "https://")):
            urls.append(url)
    return urls


def filter_in_scope(urls: list[str], guard: Guard) -> tuple[list[str], int]:
    """Second scope layer: drop (never re-surface) out-of-scope URLs."""
    in_scope: list[str] = []
    dropped = 0
    seen: set[str] = set()
    for u in urls:
        if u in seen:
            continue
        seen.add(u)
        try:
            guard.authorize(u)
        except ScopeViolation:
            dropped += 1
            continue
        in_scope.append(u)
    return in_scope, dropped


class KatanaTool(Tool):
    name = "katana_scan"
    description = (
        "Crawl an authorized web origin with katana: discovers linked pages, "
        "JS endpoints and parameters up to a depth limit. Returns in-scope URLs "
        "only. Use it after web_probe to map the attack surface before "
        "vulnerability scanning."
    )
    binary = "katana"
    parameters = {
        "type": "object",
        "properties": {
            "url": {"type": "string", "description": "Seed URL (must be in scope)"},
            "depth": {"type": "integer", "description": "Crawl depth, default 2 (max 5)"},
            "javascript_crawl": {
                "type": "boolean",
                "description": "Also extract endpoints from JavaScript files. Default true.",
            },
            "rate": {
                "type": "integer",
                "description": "Requests per second, default 30 (max 100)",
            },
        },
        "required": ["url"],
    }

    def __init__(self, guard: Guard):
        self.guard = guard

    def run(self, args: dict[str, Any]) -> ToolResult:
        url = str(args["url"])
        depth = max(1, min(int(args.get("depth") or 2), 5))
        rate = max(1, min(int(args.get("rate") or 30), 100))
        cmd = [
            "katana", "-u", url,
            "-d", str(depth),
            "-jsonl", "-silent",
            "-timeout", "10",
            "-retry", "1",
            "-fs", "rdn",       # first layer: stay on the target's root domain
            "-duc",             # no update checks in automated runs
            "-rl", str(rate),   # requests/sec cap (katana default 150 is too loud)
            "-mdp", "100",      # cap pages per domain (crawler-trap protection)
        ]
        if args.get("javascript_crawl", True):
            cmd.append("-jc")

        proc = self.shell(cmd, timeout=900)
        raw_urls = parse_katana_jsonl(proc.stdout)
        if not raw_urls and proc.returncode != 0:
            raise ToolError(f"katana failed (rc={proc.returncode}): {proc.stderr[:300]}")

        in_scope, dropped = filter_in_scope(raw_urls, self.guard)

        # Origin-only dedup list + full URL list both matter downstream
        origins = sorted({urlparse(u).scheme + "://" + urlparse(u).netloc for u in in_scope})
        summary = (
            f"katana discovered {len(in_scope)} in-scope URL(s) "
            f"across {len(origins)} origin(s)"
            + (f"; {dropped} out-of-scope URL(s) dropped" if dropped else "")
        )
        return ToolResult(
            ok=True,
            summary=summary,
            data={"urls": in_scope[:200], "origins": origins, "dropped_out_of_scope": dropped},
            raw="\n".join(in_scope),
        )
