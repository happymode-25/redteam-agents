"""Scoped HTTP request tool: lets the exploit agent send crafted requests.

Responses are truncated before entering agent context. Every call passes
through ScopeGuard, and the orchestrator adds a human-confirmation hook
for this tool specifically.
"""

from __future__ import annotations

from typing import Any

import requests

from ..http import ScopedHttpError, ScopedSession
from ..scope import Guard
from .base import Tool, ToolError, ToolResult

MAX_RESPONSE_CHARS = 4000


class HttpRequestTool(Tool):
    name = "http_request"
    description = (
        "Send a single HTTP request to an authorized URL (verification/PoC only: "
        "read-only requests, no destructive methods). Use it to confirm a "
        "vulnerability, probe an endpoint, or capture response evidence. "
        "Response body is truncated."
    )
    parameters = {
        "type": "object",
        "properties": {
            "url": {"type": "string", "description": "Full URL (must be in scope)"},
            "method": {
                "type": "string",
                "enum": ["GET", "HEAD", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"],
                "description": "HTTP method. GET/HEAD are read-only; anything else is treated as active.",
            },
            "headers": {
                "type": "object",
                "additionalProperties": {"type": "string"},
                "description": "Optional request headers",
            },
            "body": {"type": "string", "description": "Optional request body"},
        },
        "required": ["url", "method"],
    }

    def __init__(self, guard: Guard):
        self.guard = guard

    def run(self, args: dict[str, Any]) -> ToolResult:
        url = str(args["url"])
        method = str(args.get("method", "GET")).upper()
        headers = {str(k): str(v) for k, v in (args.get("headers") or {}).items()}
        body = args.get("body")

        session = ScopedSession(self.guard, timeout=20)
        try:
            resp = session.request(
                method,
                url,
                headers=headers,
                data=body if body is not None else None,
                timeout=20,
                allow_redirects=True,
                verify=True,
            )
        except (requests.RequestException, ScopedHttpError) as exc:
            raise ToolError(f"request to {url} failed: {exc}") from exc

        interesting = {
            k: v for k, v in resp.headers.items()
            if k.lower() in ("server", "content-type", "set-cookie", "location",
                             "www-authenticate", "x-powered-by")
        }
        data = {
            "status_code": resp.status_code,
            "final_url": resp.url,
            "headers": {k: v[:200] for k, v in interesting.items()},
            "body_preview": resp.text[:MAX_RESPONSE_CHARS],
            "body_length": len(resp.content),
        }
        summary = f"{method} {url} -> HTTP {resp.status_code} ({len(resp.content)} bytes)"
        return ToolResult(ok=True, summary=summary, data=data)
