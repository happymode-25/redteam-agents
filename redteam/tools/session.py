"""Session lifecycle tools (Phase 2.1): agents can log in as configured
identities, inspect session state (names/verification only), and log out.

Secrets never appear in tool arguments, results, or summaries — identities
are referenced by name; credentials come from env vars at login time and
pass through the redaction pass.
"""

from __future__ import annotations

from typing import Any

from ..auth import SessionManager
from .base import Tool, ToolResult


class SessionLoginTool(Tool):
    name = "session_login"
    description = (
        "Log in as a configured test identity (identity names come from the "
        "operator's config, never from you). Returns login and verification "
        "state. Required before any authenticated test (IDOR/BOLA, BFLA, "
        "authenticated session checks). Logging in does not modify target "
        "data — it only establishes a session."
    )
    binary = None
    parameters = {
        "type": "object",
        "properties": {
            "identity": {
                "type": "string",
                "description": "Configured identity name (see session_status)",
            },
        },
        "required": ["identity"],
    }

    def __init__(self, sessions: SessionManager):
        self.sessions = sessions

    def run(self, args: dict[str, Any]) -> ToolResult:
        meta = self.sessions.login(str(args["identity"]))
        return ToolResult(
            ok=True,
            summary=f"logged in as '{meta.name}' ({meta.kind}, "
                    f"verified={meta.verified}) — {meta.note}",
            data=meta.summary(),
        )


class SessionStatusTool(Tool):
    name = "session_status"
    description = (
        "List configured test identities and their login/verification state. "
        "Shows names and kinds only — never credentials. Check this before "
        "authenticated tests to see which identities exist and which are "
        "logged in."
    )
    binary = None
    parameters = {"type": "object", "properties": {}, "required": []}

    def __init__(self, sessions: SessionManager):
        self.sessions = sessions

    def run(self, args: dict[str, Any]) -> ToolResult:
        rows = self.sessions.status()
        logged = sum(1 for r in rows if r["logged_in"])
        verified = sum(1 for r in rows if r["verified"])
        return ToolResult(
            ok=True,
            summary=f"{len(rows)} configured identity(ies): {logged} logged in, "
                    f"{verified} verified",
            data={"identities": rows},
        )


class SessionLogoutTool(Tool):
    name = "session_logout"
    description = (
        "Terminate a session (drops the cookie jar and auth headers). Call "
        "when finished with authenticated testing so no live session lingers."
    )
    binary = None
    parameters = {
        "type": "object",
        "properties": {
            "identity": {
                "type": "string",
                "description": "Identity to log out; omit to log out all",
            },
        },
        "required": [],
    }

    def __init__(self, sessions: SessionManager):
        self.sessions = sessions

    def run(self, args: dict[str, Any]) -> ToolResult:
        identity = str(args.get("identity", "")).strip()
        if identity:
            ended = self.sessions.logout(identity)
            summary = (f"logged out '{identity}'" if ended
                       else f"'{identity}' had no active session")
            return ToolResult(ok=True, summary=summary, data={"ended": ended})
        count = self.sessions.logout_all()
        return ToolResult(ok=True, summary=f"logged out {count} session(s)",
                          data={"ended": count})
