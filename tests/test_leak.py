"""Phase 2 exit gate — zero credential leaks.

The threat: an agent (or a cooperating target echoing our credentials
back) copies secret material into tool observations, findings, the audit
log, or the report. This suite drives every real output surface through a
simulated authenticated engagement with deliberately leaky inputs and
asserts that NO registered secret survives in ANY of them:

  * the observation string handed to the hosted LLM,
  * audit.jsonl (dictionary-attack detail + hash chain intact),
  * findings JSON (state.save),
  * the rendered report markdown,
  * login failure messages (target echoing the password back).
"""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from redteam.agents.base import Agent
from redteam.audit import AuditLog, verify_chain
from redteam.auth import SessionManager
from redteam.config import IdentityConfig
from redteam.redact import REDACTED, redactor
from redteam.report import render_report
from redteam.state import SharedState
from redteam.tools.base import Tool, ToolError, ToolRegistry, ToolResult

from test_phase1 import make_guard

PASSWORD = "Sup3rS3cret-Passw0rd!"
COOKIE = "session=abc123tokenvalue; role=user"
BEARER = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sigvalue123"
USERNAME = "alice@shop.test"

SECRETS = (PASSWORD, COOKIE, BEARER, USERNAME)


class FakeResponse:
    def __init__(self, status=200, text="", body=None):
        self.status_code = status
        self.text = text
        self._body = body

    def json(self):
        if self._body is None:
            raise ValueError("no json")
        return self._body


class FakeScopedSession:
    queue: list[FakeResponse] = []

    def __init__(self, guard=None, **kwargs):
        self.headers: dict[str, str] = {}
        self.jar: dict[str, str] = {}

    def set_default_header(self, name, value):
        self.headers[name] = value

    def cookies(self) -> dict[str, str]:
        return dict(self.jar)

    def cookie_header(self) -> str:
        return self.headers.get("Cookie", "")

    def request(self, method, url, headers=None, data=None, json=None,
                timeout=None, allow_redirects=True, verify=None):
        resp = FakeScopedSession.queue.pop(0) if FakeScopedSession.queue \
            else FakeResponse()
        self.jar.update(getattr(resp, "set_cookies", {}) or {})
        return resp

    def get(self, url, **kwargs):
        return self.request("GET", url, **kwargs)


class EchoTool(Tool):
    """Worst case: a tool whose output carries raw secret material."""
    name = "echo_secret"
    description = "test-only tool that echoes its input"
    binary = None
    parameters = {"type": "object",
                  "properties": {"text": {"type": "string"}},
                  "required": ["text"]}

    def run(self, args):
        text = str(args.get("text", ""))
        return ToolResult(ok=True, summary=f"echoed raw value: {text}",
                          data={"echo": text})


FORM = IdentityConfig(
    name="alice", kind="form",
    login_url="https://shop.test/rest/user/login",
    username_env="LEAK_USER", password_env="LEAK_PASS",
    verify_url="https://shop.test/rest/user/whoami", verify_marker="alice",
)

COOKIE_IDENT = IdentityConfig(name="bob", kind="cookie",
                              cookie_env="LEAK_COOKIE")


class TestCredentialLeakGate(unittest.TestCase):
    def setUp(self):
        redactor.clear()
        FakeScopedSession.queue = []
        os.environ["LEAK_USER"] = USERNAME
        os.environ["LEAK_PASS"] = PASSWORD
        os.environ["LEAK_COOKIE"] = COOKIE
        self.patcher = mock.patch("redteam.auth.ScopedSession",
                                  FakeScopedSession)
        self.patcher.start()
        self.addCleanup(self.patcher.stop)
        self.tmp = Path(tempfile.mkdtemp())

    def tearDown(self):
        redactor.clear()
        for key in ("LEAK_USER", "LEAK_PASS", "LEAK_COOKIE"):
            os.environ.pop(key, None)

    def _assert_clean(self, label: str, text: str):
        for secret in SECRETS:
            self.assertNotIn(secret, text,
                             f"credential leaked into {label}")

    def test_no_secret_survives_any_output_surface(self):
        audit = AuditLog(self.tmp / "audit.jsonl")
        state = SharedState()
        sessions = SessionManager([FORM, COOKIE_IDENT], make_guard(),
                                  audit=audit)

        # 1) form login against a target that ECHOES the credentials back in
        #    its (token-bearing) response — worst case for every sink
        FakeScopedSession.queue = [
            FakeResponse(200, text=f"{{'password': '{PASSWORD}'}}",
                         body={"authentication": {"token": BEARER,
                                                  "note": PASSWORD}}),
            FakeResponse(200, text=f"alice {PASSWORD}"),
        ]
        meta = sessions.login("alice")
        self.assertTrue(meta.verified)

        # 2) static cookie identity — its secret registers on login too
        sessions.login("bob")
        self.assertTrue(sessions.is_logged_in("bob"))

        # 2) findings where the agent pastes raw leaky output into evidence
        state.add_finding(
            "Login echoes credentials",
            "high",
            "https://shop.test/rest/user/login",
            evidence=(f"request body: password={PASSWORD}\n"
                      f"response: password='{PASSWORD}' (status 200)"),
            remediation="Do not reflect credentials.",
            status="confirmed",
        )
        state.add_finding(
            "Session cookie exposed",
            "medium",
            "https://shop.test/",
            evidence=(f"Set-Cookie: {COOKIE}\n"
                      f"Authorization: Bearer {BEARER}"),
            status="confirmed",
        )

        # 4) login failure where the target echoes the password in a 401
        FakeScopedSession.queue = [
            FakeResponse(401, text=f"bad password: {PASSWORD}")]
        with self.assertRaises(ToolError) as cm:
            sessions.login("alice")
        self._assert_clean("ToolError message", str(cm.exception))

        # 5) observation channel to the hosted LLM: a leaky tool result
        registry = ToolRegistry([EchoTool()])
        agent = Agent(name="analyst", role="analysis", system_prompt="x",
                      router=None, registry=registry, guard=make_guard(),
                      state=state, audit=audit, emit=lambda _s: None)
        observation = agent._execute_tool("echo_secret", {"text": PASSWORD})
        self.assertIn(REDACTED, observation)
        self._assert_clean("LLM observation", observation)

        # 6) rendered report (narrative deliberately includes a secret)
        markdown = render_report(
            target="https://shop.test",
            narrative=f"Operator note: the password {PASSWORD} was reused.",
            state=state,
        )
        self._assert_clean("report markdown", markdown)

        # 7) findings JSON on disk
        findings_path = self.tmp / "findings.json"
        state.save(findings_path)
        self._assert_clean("findings.json",
                           findings_path.read_text(encoding="utf-8"))

        # 8) audit log on disk — and the hash chain must still verify
        audit_text = (self.tmp / "audit.jsonl").read_text(encoding="utf-8")
        self._assert_clean("audit.jsonl", audit_text)
        ok, msg = verify_chain(self.tmp / "audit.jsonl")
        self.assertTrue(ok, msg)

        # the audit log must actually contain the events we exercised
        self.assertIn("session_login_failed", audit_text)
        self.assertIn("tool_call", audit_text)

    def test_redaction_is_registered_by_login_not_by_config(self):
        """Before any login resolves env vars, nothing is registered — the
        vault holds VAR NAMES, and only login turns them into scrubbable
        values."""
        self.assertEqual(redactor.count, 0)
        sessions = SessionManager([FORM], make_guard())
        FakeScopedSession.queue = [FakeResponse(200, text="alice"),
                                   FakeResponse(200, text="alice")]
        sessions.login("alice")
        self.assertGreaterEqual(redactor.count, 2)  # username + password
        self.assertNotIn(PASSWORD, json.dumps(sessions.status()))


if __name__ == "__main__":
    unittest.main()
