"""API surface discovery (catalog section 4 pre-work).

Pure Python via ScopedSession: finds OpenAPI/Swagger specs, GraphQL
endpoints (and tests introspection with a single read-only query), and
API roots. Returns a structured inventory the analyst agent can scan.
"""

from __future__ import annotations

import json
from typing import Any
from urllib.parse import urljoin, urlparse

import requests

from ..http import ScopedHttpError, ScopedSession
from ..scope import Guard
from .base import Tool, ToolError, ToolResult

SPEC_PATHS = [
    "/.well-known/openapi.json",
    "/openapi.json",
    "/openapi.yaml",
    "/swagger.json",
    "/swagger/v1/swagger.json",
    "/v2/api-docs",
    "/v3/api-docs",
    "/api-docs",
    "/swagger-ui.html",
    "/swagger/index.html",
    "/redoc",
    "/.well-known/apis.json",
]

GRAPHQL_PATHS = ["/graphql", "/gql", "/graphiql", "/api/graphql", "/v1/graphql"]

INTROSPECTION_QUERY = {"query": "{ __schema { queryType { name } mutationType { name } } }"}


def parse_openapi_spec(doc: dict) -> dict:
    """Extract a safe summary from an OpenAPI/Swagger document."""
    if not isinstance(doc, dict):
        return {"valid": False}
    is_openapi = "openapi" in doc or "swagger" in doc
    info = doc.get("info") or {}
    security = doc.get("components", {}).get("securitySchemes") or doc.get("securityDefinitions") or {}
    paths = doc.get("paths") or {}
    insecure_paths = [
        p for p, ops in paths.items()
        if isinstance(ops, dict)
        for meth, op in ops.items()
        if meth.lower() in ("get", "post", "put", "delete", "patch")
        if isinstance(op, dict) and not op.get("security") and not doc.get("security")
    ]
    return {
        "valid": is_openapi,
        "spec_version": doc.get("openapi") or doc.get("swagger"),
        "title": info.get("title", ""),
        "api_version": info.get("version", ""),
        "servers": [s.get("url") for s in (doc.get("servers") or []) if isinstance(s, dict)][:5],
        "path_count": len(paths),
        "paths_sample": sorted(paths)[:50],
        "auth_schemes": sorted(security)[:20],
        "paths_without_security": insecure_paths[:20],
    }


class ApiDiscoveryTool(Tool):
    name = "api_discovery"
    description = (
        "Map the API surface of an authorized origin: locate OpenAPI/Swagger "
        "specifications (and summarize their paths/auth), find GraphQL "
        "endpoints, and test GraphQL introspection with one read-only query. "
        "GET/HEAD requests plus a single introspection POST."
    )
    parameters = {
        "type": "object",
        "properties": {
            "url": {"type": "string", "description": "Origin URL, e.g. https://example.com"},
            "check_graphql": {
                "type": "boolean",
                "description": "Probe GraphQL endpoints incl. introspection. Default true.",
            },
        },
        "required": ["url"],
    }

    def __init__(self, guard: Guard):
        self.guard = guard

    def run(self, args: dict[str, Any]) -> ToolResult:
        base = str(args["url"]).rstrip("/") + "/"
        session = ScopedSession(self.guard, timeout=10, max_redirects=3)
        findings: dict[str, Any] = {"specs": [], "graphql": [], "notes": []}

        for path in SPEC_PATHS:
            target = urljoin(base, path.lstrip("/"))
            try:
                resp = session.get(target, timeout=8, allow_redirects=True)
            except (requests.RequestException, ScopedHttpError):
                continue
            if resp.status_code != 200 or len(resp.content) == 0:
                continue
            if "json" not in resp.headers.get("Content-Type", "").lower() and \
               not path.endswith(".json"):
                # swagger-ui.html / redoc: record exposure, no spec parse
                findings["specs"].append({"url": resp.url, "ui_exposed": True})
                findings["notes"].append(f"Swagger UI exposed at {resp.url}")
                continue
            try:
                doc = resp.json()
            except (ValueError, json.JSONDecodeError):
                continue
            summary = parse_openapi_spec(doc if isinstance(doc, dict) else {})
            if summary.get("valid"):
                summary["url"] = resp.url
                findings["specs"].append(summary)
                findings["notes"].append(
                    f"API spec '{summary['title']}' with {summary['path_count']} "
                    f"paths at {resp.url}"
                )
                if summary["paths_without_security"]:
                    findings["notes"].append(
                        f"{len(summary['paths_without_security'])} documented path(s) "
                        "declare no security requirement"
                    )

        if args.get("check_graphql", True):
            for path in GRAPHQL_PATHS:
                target = urljoin(base, path.lstrip("/"))
                try:
                    resp = session.request("POST", target, json=INTROSPECTION_QUERY,
                                           timeout=8, allow_redirects=False)
                except (requests.RequestException, ScopedHttpError):
                    continue
                if resp.status_code not in (200, 400, 405):
                    continue
                body = resp.text[:2000]
                entry = {"url": target, "status_code": resp.status_code}
                if "__schema" in body:
                    entry["introspection_enabled"] = True
                    findings["notes"].append(
                        f"GraphQL introspection ENABLED at {target} (schema disclosure)"
                    )
                elif resp.status_code == 200 and ("errors" in body or "data" in body):
                    entry["introspection_enabled"] = False
                    entry["graphql_responds"] = True
                else:
                    continue
                findings["graphql"].append(entry)

        found_any = findings["specs"] or findings["graphql"]
        summary = (
            f"API discovery: {len(findings['specs'])} spec(s), "
            f"{len(findings['graphql'])} GraphQL endpoint(s); "
            f"{len(findings['notes'])} note(s)"
        )
        if not found_any:
            summary = "API discovery: no exposed specs or GraphQL endpoints found"
        return ToolResult(ok=True, summary=summary, data=findings)
