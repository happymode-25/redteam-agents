"""Phase 2.2 — BFLA checks + response schema diff.

Pure decision-function tests for bfla_verdict()/schema_verdict() plus
tool-level tests with injected/patched sessions (zero network).
"""

from __future__ import annotations

import json
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest import mock

from redteam.auth import SessionManager
from redteam.config import IdentityConfig, load_config
from redteam.redact import redactor
from redteam.tools.base import ToolError
from redteam.tools.bfla import BflaCheckTool, bfla_verdict
from redteam.tools.schema import (SchemaDiffTool, json_paths, parse_paths,
                                  schema_verdict)

from test_phase1 import make_guard


class FakeResponse:
    def __init__(self, status=200, text=""):
        self.status_code = status
        self.text = text


class FakeSession:
    def __init__(self, responses=None, raise_exc=None):
        self.responses = list(responses or [])
        self.raise_exc = raise_exc
        self.calls = []

    def request(self, method, url, **kwargs):
        if self.raise_exc is not None:
            raise self.raise_exc
        self.calls.append((method, url))
        return self.responses.pop(0) if self.responses else FakeResponse()

    def get(self, url, **kwargs):
        return self.request("GET", url, **kwargs)


def make_sessions(**logins: FakeSession) -> SessionManager:
    idents = [IdentityConfig(name=n, kind="bearer", token_env="T") for n in logins]
    mgr = SessionManager(idents, make_guard())
    for name, fake in logins.items():
        mgr._sessions[name] = fake
    return mgr


ADMIN_BODY = json.dumps({"status": "success", "data": {"users": 3,
                         "adminMail": "root@shop.test", "role": "admin",
                         "since": "2024-06-01"}})

LOWPRIV_DASHBOARD = json.dumps({"status": "success",
                                "data": {"orders": 0, "cart": []}})


class TestBflaVerdict(unittest.TestCase):
    def test_privileged_identity_denied_is_inconclusive(self):
        v = bfla_verdict(404, 404, "nope", "nope")
        self.assertEqual(v["verdict"], "inconclusive")

    def test_marker_missing_from_privileged_is_inconclusive(self):
        v = bfla_verdict(200, 200, ADMIN_BODY, ADMIN_BODY, "absent-marker")
        self.assertEqual(v["verdict"], "inconclusive")
        self.assertFalse(v["marker_found_in_a"])

    def test_lowpriv_denied_is_ok(self):
        v = bfla_verdict(200, 403, ADMIN_BODY, "forbidden")
        self.assertEqual(v["verdict"], "access_control_ok")

    def test_soft_denial_200_is_ok(self):
        v = bfla_verdict(200, 200, ADMIN_BODY,
                         '{"error": "unauthorized"}')
        self.assertEqual(v["verdict"], "access_control_ok")

    def test_marker_in_lowpriv_is_confirmed(self):
        v = bfla_verdict(200, 200, ADMIN_BODY,
                         ADMIN_BODY.replace("users", "users"), 
                         "root@shop.test")
        self.assertEqual(v["verdict"], "confirmed")
        self.assertTrue(v["marker_found_in_b"])

    def test_marker_privileged_only_is_ok(self):
        v = bfla_verdict(200, 200, ADMIN_BODY, LOWPRIV_DASHBOARD,
                         "root@shop.test")
        self.assertEqual(v["verdict"], "access_control_ok")
        self.assertTrue(v["marker_found_in_a"])
        self.assertFalse(v["marker_found_in_b"])

    def test_identical_bodies_no_marker_is_confirmed(self):
        v = bfla_verdict(200, 200, ADMIN_BODY, ADMIN_BODY)
        self.assertEqual(v["verdict"], "confirmed")
        self.assertGreaterEqual(v["overlap"], 0.8)

    def test_different_success_is_suspected(self):
        v = bfla_verdict(200, 200, ADMIN_BODY, LOWPRIV_DASHBOARD)
        self.assertEqual(v["verdict"], "suspected")
        self.assertIn("reachable", v["reason"])


class TestBflaTool(unittest.TestCase):
    def test_normal_run_returns_pair_evidence(self):
        a = FakeSession([FakeResponse(200, ADMIN_BODY)])
        b = FakeSession([FakeResponse(403, "forbidden")])
        tool = BflaCheckTool(make_sessions(admin=a, guest=b))
        res = tool.run({"url": "https://shop.test/api/admin/users",
                        "identity_privileged": "admin",
                        "identity_lowpriv": "guest"})
        self.assertEqual(res.data["verdict"], "access_control_ok")
        self.assertIn("privileged=admin:", res.data["evidence"])
        self.assertIn("status 403", res.data["evidence"])
        self.assertIn("do NOT record", res.data["recommendation"])
        self.assertEqual(a.calls[0][0], "GET")

    def test_same_identity_rejected(self):
        tool = BflaCheckTool(make_sessions(admin=FakeSession()))
        with self.assertRaises(ToolError) as cm:
            tool.run({"url": "https://x/y", "identity_privileged": "admin",
                      "identity_lowpriv": "admin"})
        self.assertIn("DIFFERENT", str(cm.exception))

    def test_state_changing_method_rejected(self):
        tool = BflaCheckTool(make_sessions(admin=FakeSession(),
                                           guest=FakeSession()))
        with self.assertRaises(ToolError) as cm:
            tool.run({"url": "https://x/y", "identity_privileged": "admin",
                      "identity_lowpriv": "guest", "method": "POST"})
        self.assertIn("read-only", str(cm.exception))

    def test_not_logged_in_is_tool_error(self):
        tool = BflaCheckTool(make_sessions(admin=FakeSession()))
        with self.assertRaises(ToolError) as cm:
            tool.run({"url": "https://x/y", "identity_privileged": "admin",
                      "identity_lowpriv": "guest"})
        self.assertIn("session_login first", str(cm.exception))


class TestSchemaVerdict(unittest.TestCase):
    def test_anon_sensitive_value_is_confirmed(self):
        v = schema_verdict(200, '{"userId": 7, "token": "abcd1234efgh"}',
                           None, None, [])
        self.assertEqual(v["verdict"], "confirmed")
        self.assertIn("token", v["sensitive_anon_fields"])

    def test_anon_sensitive_empty_value_not_confirmed(self):
        v = schema_verdict(200, '{"token": ""}', None, None, [])
        self.assertEqual(v["verdict"], "no_issue")
        self.assertEqual(v["sensitive_anon_fields"], [])

    def test_csrf_in_anon_is_not_a_finding(self):
        v = schema_verdict(200, '{"csrfToken": "xyz123", "page": "login"}',
                           None, None, [])
        self.assertEqual(v["verdict"], "no_issue")

    def test_expected_fields_extras_are_suspected(self):
        body = json.dumps({"id": 1, "name": "a", "internalNotes": "x",
                           "debug": True})
        v = schema_verdict(200, body, 200, body, ["id", "name"])
        self.assertEqual(v["verdict"], "suspected")
        self.assertIn("internalNotes", v["extra_fields"])

    def test_exact_documented_schema_is_no_issue(self):
        body = json.dumps({"id": 1, "name": "a"})
        v = schema_verdict(200, body, 200, body, ["id", "name"])
        self.assertEqual(v["verdict"], "no_issue")
        self.assertEqual(v["extra_fields"], [])

    def test_non_json_is_inconclusive(self):
        v = schema_verdict(200, "<html>hi</html>", 200, "<html>hi</html>", [])
        self.assertEqual(v["verdict"], "inconclusive")

    def test_anon_denied_no_expected_is_inconclusive(self):
        v = schema_verdict(401, "unauthorized", None, None, [])
        self.assertEqual(v["verdict"], "inconclusive")

    def test_auth_baseline_when_anon_denied(self):
        body = json.dumps({"id": 1, "name": "a", "salary": 9})
        v = schema_verdict(401, "unauthorized", 200, body, ["id", "name"])
        self.assertEqual(v["verdict"], "suspected")
        self.assertEqual(v["extra_fields"], ["salary"])

    def test_auth_only_fields_reported_as_context(self):
        v = schema_verdict(200, '{"a": 1}', 200, '{"a": 1, "b": 2}', [])
        self.assertEqual(v["verdict"], "no_issue")
        self.assertEqual(v["auth_only_fields"], ["b"])

    def test_json_paths_flattening(self):
        paths = json_paths({"user": {"email": "a@b", "tags": ["x"]}})
        self.assertIn("user.email", paths)
        self.assertIn("user.tags", paths)
        self.assertIn("user.tags[*]", paths)
        self.assertIsNone(parse_paths("not json"))


class TestSchemaTool(unittest.TestCase):
    def _tool(self, anon: FakeSession, **logins) -> SchemaDiffTool:
        patcher = mock.patch("redteam.tools.schema.ScopedSession",
                             lambda guard, **kw: anon)
        patcher.start()
        self.addCleanup(patcher.stop)
        return SchemaDiffTool(make_sessions(**logins))

    def test_confirmed_anonymous_exposure(self):
        anon = FakeSession([FakeResponse(
            200, '{"userId": 7, "token": "abcd1234efgh"}')])
        tool = self._tool(anon)
        res = tool.run({"url": "https://shop.test/api/profile"})
        self.assertEqual(res.data["verdict"], "confirmed")
        self.assertIn("status 200", res.data["evidence"])
        self.assertIn("record_finding", res.data["recommendation"])

    def test_authenticated_diff_with_expected_fields(self):
        anon = FakeSession([FakeResponse(200, '{"id": 1, "name": "a"}')])
        auth = FakeSession([FakeResponse(
            200, '{"id": 1, "name": "a", "ssn": "123-45-6789"}')])
        tool = self._tool(anon, alice=auth)
        res = tool.run({"url": "https://shop.test/api/me",
                        "identity": "alice",
                        "expected_fields": ["id", "name"]})
        # auth body has an extra sensitive field beyond docs
        self.assertEqual(res.data["verdict"], "suspected")
        self.assertIn("ssn", res.data["extra_fields"])

    def test_identity_not_logged_in_fails_before_network(self):
        anon = FakeSession([])  # must never be called
        tool = self._tool(anon)  # no sessions at all
        with self.assertRaises(ToolError) as cm:
            tool.run({"url": "https://shop.test/x", "identity": "alice"})
        self.assertIn("session_login first", str(cm.exception))
        self.assertEqual(anon.calls, [])

    def test_evidence_is_redacted(self):
        redactor.clear()
        self.addCleanup(redactor.clear)
        redactor.register("tok-en-abcdef123")
        anon = FakeSession([FakeResponse(
            200, '{"token": "tok-en-abcdef123", "id": 1}')])
        tool = self._tool(anon)
        res = tool.run({"url": "https://shop.test/x"})
        self.assertNotIn("tok-en-abcdef123", res.data["evidence"])


class TestCoverageHonesty(unittest.TestCase):
    """The matrix must never claim authenticated work that did not run."""

    @staticmethod
    def _row(markdown: str, prefix: str) -> str:
        for line in markdown.splitlines():
            if line.startswith(f"| {prefix}"):
                return line
        raise AssertionError(f"row {prefix!r} not found")

    def test_default_keeps_gated_rows(self):
        from redteam.coverage import render_coverage
        md = render_coverage()
        self.assertIn("NEEDS CREDS", self._row(md, "3. Authorization"))

    def test_configured_but_unused_still_needs_creds(self):
        from redteam.coverage import render_coverage
        md = render_coverage(identities=True, tools_used={"session_login"})
        row = self._row(md, "3. Authorization")
        self.assertIn("NEEDS CREDS", row)
        self.assertIn("identities ARE configured", row)

    def test_idor_run_upgrades_section_3(self):
        from redteam.coverage import render_coverage
        md = render_coverage(identities=True, tools_used={"idor_diff"})
        row = self._row(md, "3. Authorization")
        self.assertIn("CHECKED", row)
        self.assertIn("idor_diff", row)

    def test_jwt_run_upgrades_section_2_to_partial(self):
        from redteam.coverage import render_coverage
        md = render_coverage(identities=True, tools_used={"jwt_check"})
        row = self._row(md, "2. Authentication")
        self.assertIn("PARTIAL", row)
        self.assertIn("jwt_check", row)

    def test_enum_and_lifecycle_upgrade_section_2(self):
        from redteam.coverage import render_coverage
        md = render_coverage(identities=True,
                             tools_used={"account_enum", "session_check"})
        row = self._row(md, "2. Authentication")
        self.assertIn("PARTIAL", row)
        self.assertIn("account_enum", row)
        self.assertIn("session_check", row)

    def test_schema_run_notes_api_authz(self):
        from redteam.coverage import render_coverage
        md = render_coverage(identities=True,
                             tools_used={"schema_diff", "bfla_check"})
        row = self._row(md, "4. API Security")
        self.assertIn("PARTIAL", row)
        self.assertIn("authenticated:", row)

    def test_business_logic_reworded_not_claimed(self):
        from redteam.coverage import render_coverage
        md = render_coverage(identities=True, tools_used={"session_login"})
        row = self._row(md, "11. Business Logic")
        self.assertIn("authenticated session available", row)
        self.assertIn("not exercised this run", row)

    def test_business_logic_upgraded_only_when_workflow_tools_ran(self):
        from redteam.coverage import render_coverage
        md = render_coverage(identities=True,
                             tools_used={"workflow_step", "race_burst"})
        row = self._row(md, "11. Business Logic")
        self.assertIn("PARTIAL", row)
        self.assertIn("workflow_step", row)
        self.assertIn("race_burst", row)

    def test_report_passes_coverage_context_through(self):
        from redteam.report import render_report
        from redteam.state import SharedState
        md = render_report("https://shop.test", "n", SharedState(),
                           identities=True, tools_used={"idor_diff"})
        self.assertIn("CHECKED", self._row(md, "3. Authorization"))


class TestWiring(unittest.TestCase):
    def test_authz_tools_registered_in_orchestrator(self):
        root = Path(__file__).resolve().parent.parent
        cfg = load_config(root / "config.example.yaml")
        tmp = Path(tempfile.mkdtemp())
        cfg = replace(cfg, safety=replace(
            cfg.safety, artifacts_dir=str(tmp / "art"),
            cassette_dir=str(tmp / "cass"), runner="local"))
        from redteam.orchestrator import Orchestrator
        orch = Orchestrator(cfg)
        for tool_name in ("bfla_check", "schema_diff"):
            self.assertIsNotNone(orch.registry.get(tool_name), tool_name)


if __name__ == "__main__":
    unittest.main()
