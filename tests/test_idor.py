"""Phase 2.2 — IDOR/BOLA diff engine.

The verdict logic is deterministic code: these tests call verdict_for()
directly for every branch, then exercise the tool with injected fake
sessions (no network, no login needed — sessions are placed into the
manager directly).
"""

from __future__ import annotations

import json
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from redteam.auth import SessionManager
from redteam.config import IdentityConfig, load_config
from redteam.redact import redactor
from redteam.scope import ScopeViolation
from redteam.tools.base import ToolError
from redteam.tools.idor import (IdoDiffTool, SIMILARITY_THRESHOLD, similarity,
                                verdict_for)

from test_phase1 import make_guard


class FakeResponse:
    def __init__(self, status=200, text=""):
        self.status_code = status
        self.text = text


class FakeHTTPSession:
    """Stands in for a logged-in ScopedSession: serves a response queue."""

    def __init__(self, responses: list[FakeResponse] | None = None,
                 raise_exc: Exception | None = None):
        self.responses = list(responses or [])
        self.raise_exc = raise_exc
        self.calls: list[tuple[str, str]] = []

    def request(self, method, url, **kwargs):
        if self.raise_exc is not None:
            raise self.raise_exc
        self.calls.append((method, url))
        if self.responses:
            return self.responses.pop(0)
        return FakeResponse()


def make_sessions(**logins: FakeHTTPSession) -> SessionManager:
    """Manager with identities already 'logged in' to fake sessions."""
    idents = [IdentityConfig(name=n, kind="bearer", token_env="T") for n in logins]
    mgr = SessionManager(idents, make_guard())
    for name, fake in logins.items():
        mgr._sessions[name] = fake
    return mgr


OWNER_BODY = json.dumps({
    "id": 123, "email": "alice@shop.test", "name": "Alice",
    "role": "admin", "createdAt": "2026-01-01",
})


class TestVerdictFunction(unittest.TestCase):
    """Pure branches — no sessions, no network."""

    def test_marker_in_both_is_confirmed(self):
        v = verdict_for(200, 200, OWNER_BODY,
                        OWNER_BODY.replace("Alice", "Alice"), "alice@shop.test")
        self.assertEqual(v["verdict"], "confirmed")
        self.assertTrue(v["marker_found_in_b"])

    def test_a_cannot_read_is_inconclusive(self):
        v = verdict_for(404, 404, "not found", "not found", "")
        self.assertEqual(v["verdict"], "inconclusive")
        self.assertIn("identity A got HTTP 404", v["reason"])

    def test_marker_missing_from_a_is_inconclusive(self):
        v = verdict_for(200, 200, OWNER_BODY, OWNER_BODY, "nobody@x")
        self.assertEqual(v["verdict"], "inconclusive")
        self.assertFalse(v["marker_found_in_a"])

    def test_b_denied_is_access_control_ok(self):
        v = verdict_for(200, 403, OWNER_BODY, "forbidden", "")
        self.assertEqual(v["verdict"], "access_control_ok")
        self.assertIn("HTTP 403", v["reason"])

    def test_marker_in_a_only_is_access_control_ok(self):
        v = verdict_for(200, 200, OWNER_BODY,
                        '{"id": 123, "email": "bob@shop.test"}',
                        "alice@shop.test")
        self.assertEqual(v["verdict"], "access_control_ok")
        self.assertTrue(v["marker_found_in_a"])
        self.assertFalse(v["marker_found_in_b"])

    def test_b_error_status_is_access_control_ok(self):
        v = verdict_for(200, 404, OWNER_BODY, "gone", "alice@shop.test")
        # marker IS in A; B got404 -> denied branch hits before marker branch
        self.assertEqual(v["verdict"], "access_control_ok")

    def test_near_identical_bodies_without_marker_is_suspected(self):
        other = OWNER_BODY  # same object returned to both
        v = verdict_for(200, 200, OWNER_BODY, other, "")
        self.assertEqual(v["verdict"], "suspected")
        self.assertGreaterEqual(v["overlap"], SIMILARITY_THRESHOLD)

    def test_different_bodies_without_marker_is_inconclusive(self):
        b = json.dumps({"id": 9, "email": "carol@shop.test", "name": "Carol",
                        "role": "customer", "createdAt": "2026-02-02"})
        v = verdict_for(200, 200, OWNER_BODY, b, "")
        self.assertEqual(v["verdict"], "inconclusive")

    def test_markers_reported_in_result(self):
        v = verdict_for(200, 200, OWNER_BODY, OWNER_BODY, "alice@shop.test")
        self.assertTrue(v["marker_found_in_a"])
        self.assertEqual(v["status_a"], 200)


class TestSimilarity(unittest.TestCase):
    def test_json_containment(self):
        overlap, shared = similarity(OWNER_BODY, OWNER_BODY)
        self.assertEqual(overlap, 1.0)
        self.assertGreaterEqual(shared, 3)

    def test_line_fallback_for_html(self):
        html_a = "<html>\n<body>alice data</body>\n</html>"
        html_b = "<html>\n<body>alice data</body>\n</html>"
        overlap, _ = similarity(html_a, html_b)
        self.assertEqual(overlap, 1.0)

    def test_empty_inputs(self):
        self.assertEqual(similarity("", "x"), (0.0, 0))
        self.assertEqual(similarity("{}", "{}"), (0.0, 0))


class TestIdorTool(unittest.TestCase):
    def test_confirmed_with_marker(self):
        fake_a = FakeHTTPSession([FakeResponse(200, OWNER_BODY)])
        fake_b = FakeHTTPSession([FakeResponse(200, OWNER_BODY)])
        tool = IdoDiffTool(make_sessions(alice=fake_a, bob=fake_b))
        res = tool.run({"url": "https://shop.test/rest/user/123",
                        "identity_a": "alice", "identity_b": "bob",
                        "object_marker": "alice@shop.test"})
        self.assertEqual(res.data["verdict"], "confirmed")
        self.assertIn("record_finding", res.data["recommendation"])
        self.assertIn("confirmed", res.data["recommendation"])
        # evidence is a request/response pair with response markers
        self.assertIn("status 200", res.data["evidence"])
        self.assertIn("A=alice", res.data["evidence"])
        self.assertEqual(fake_a.calls[0][0], "GET")
        self.assertEqual(fake_b.calls[0][0], "GET")

    def test_access_control_ok_on_denial(self):
        fake_a = FakeHTTPSession([FakeResponse(200, OWNER_BODY)])
        fake_b = FakeHTTPSession([FakeResponse(403, "forbidden")])
        tool = IdoDiffTool(make_sessions(alice=fake_a, bob=fake_b))
        res = tool.run({"url": "https://shop.test/rest/user/123",
                        "identity_a": "alice", "identity_b": "bob"})
        self.assertEqual(res.data["verdict"], "access_control_ok")
        self.assertIn("do NOT record", res.data["recommendation"])

    def test_same_identity_rejected(self):
        tool = IdoDiffTool(make_sessions(alice=FakeHTTPSession()))
        with self.assertRaises(ToolError) as cm:
            tool.run({"url": "https://shop.test/x",
                      "identity_a": "alice", "identity_b": "alice"})
        self.assertIn("DIFFERENT", str(cm.exception))

    def test_state_changing_method_rejected(self):
        tool = IdoDiffTool(make_sessions(alice=FakeHTTPSession(),
                                         bob=FakeHTTPSession()))
        with self.assertRaises(ToolError) as cm:
            tool.run({"url": "https://shop.test/x", "identity_a": "alice",
                      "identity_b": "bob", "method": "DELETE"})
        self.assertIn("read-only", str(cm.exception))
        self.assertIn("GET", str(cm.exception))

    def test_head_allowed(self):
        fake_a = FakeHTTPSession([FakeResponse(200, "")])
        fake_b = FakeHTTPSession([FakeResponse(401, "")])
        tool = IdoDiffTool(make_sessions(alice=fake_a, bob=fake_b))
        res = tool.run({"url": "https://shop.test/x", "identity_a": "alice",
                        "identity_b": "bob", "method": "HEAD"})
        self.assertEqual(res.data["method"], "HEAD")

    def test_not_logged_in_identity_is_tool_error(self):
        tool = IdoDiffTool(make_sessions(alice=FakeHTTPSession()))
        with self.assertRaises(ToolError) as cm:
            tool.run({"url": "https://shop.test/x", "identity_a": "alice",
                      "identity_b": "bob"})
        self.assertIn("session_login first", str(cm.exception))

    def test_scope_violation_propagates(self):
        fake_a = FakeHTTPSession(raise_exc=ScopeViolation("out of scope"))
        tool = IdoDiffTool(make_sessions(alice=fake_a,
                                         bob=FakeHTTPSession()))
        with self.assertRaises(ScopeViolation):
            tool.run({"url": "https://evil.test/x", "identity_a": "alice",
                      "identity_b": "bob"})

    def test_evidence_is_redacted(self):
        redactor.clear()
        self.addCleanup(redactor.clear)
        redactor.register("tok-en-abcdef123")
        secret_body = '{"token": "tok-en-abcdef123", "id": 1}'
        fake_a = FakeHTTPSession([FakeResponse(200, secret_body)])
        fake_b = FakeHTTPSession([FakeResponse(200, secret_body)])
        tool = IdoDiffTool(make_sessions(alice=fake_a, bob=fake_b))
        res = tool.run({"url": "https://shop.test/x", "identity_a": "alice",
                        "identity_b": "bob"})
        self.assertNotIn("tok-en-abcdef123", res.data["evidence"])

    def test_registered_in_orchestrator(self):
        root = Path(__file__).resolve().parent.parent
        cfg = load_config(root / "config.example.yaml")
        tmp = Path(tempfile.mkdtemp())
        cfg = replace(cfg, safety=replace(
            cfg.safety, artifacts_dir=str(tmp / "art"),
            cassette_dir=str(tmp / "cass"), runner="local"))
        from redteam.orchestrator import Orchestrator
        orch = Orchestrator(cfg)
        self.assertIsNotNone(orch.registry.get("idor_diff"))


if __name__ == "__main__":
    unittest.main()
