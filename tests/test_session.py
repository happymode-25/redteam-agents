"""Phase 2.1/2.3 — session manager + session tools.

Zero network: redteam.auth.ScopedSession is replaced by a fake that
records requests and serves scripted responses. Proves the login
strategies, verification gating, no-half-open-session rule, audit
redaction, and tool wiring."""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from redteam.audit import AuditLog, verify_chain
from redteam.auth import SessionManager, _extract_bearer
from redteam.config import IdentityConfig
from redteam.redact import redactor
from redteam.scope import ScopeViolation
from redteam.tools.base import ToolError

from test_phase1 import make_guard


class FakeResponse:
    def __init__(self, status=200, text="", body=None, set_cookies=None):
        self.status_code = status
        self.text = text
        self._body = body
        self.set_cookies = set_cookies or {}

    def json(self):
        if self._body is None:
            raise ValueError("no json")
        return self._body


class FakeScopedSession:
    """Stands in for ScopedSession: records calls, serves a scripted queue."""

    queue: list[FakeResponse] = []
    raise_on_request: Exception | None = None
    instances: list = []

    def __init__(self, guard=None, **kwargs):
        self.guard = guard
        self.kwargs = kwargs
        self.headers: dict[str, str] = {}
        self.calls: list[dict] = []
        self.jar: dict[str, str] = {}
        type(self).instances.append(self)

    def set_default_header(self, name, value):
        self.headers[name] = value

    def cookies(self) -> dict[str, str]:
        return dict(self.jar)

    def cookie_header(self) -> str:
        return self.headers.get("Cookie", "")

    def request(self, method, url, headers=None, data=None, json=None,
                timeout=None, allow_redirects=True, verify=None):
        if FakeScopedSession.raise_on_request is not None:
            raise FakeScopedSession.raise_on_request
        self.calls.append({"method": method, "url": url, "data": data})
        if FakeScopedSession.queue:
            resp = FakeScopedSession.queue.pop(0)
            self.jar.update(getattr(resp, "set_cookies", {}) or {})
            return resp
        return FakeResponse()

    def get(self, url, **kwargs):
        return self.request("GET", url, **kwargs)


def make_manager(identities, audit=None):
    return SessionManager(identities, make_guard(), audit=audit)


FORM = IdentityConfig(
    name="alice", kind="form",
    login_url="https://shop.test/rest/user/login",
    username_env="T_ALICE_USER", password_env="T_ALICE_PASS",
    verify_url="https://shop.test/rest/user/whoami", verify_marker="alice",
)


class Base(unittest.TestCase):
    def setUp(self):
        redactor.clear()
        FakeScopedSession.queue = []
        FakeScopedSession.raise_on_request = None
        FakeScopedSession.instances = []
        self._patcher = mock.patch("redteam.auth.ScopedSession", FakeScopedSession)
        self._patcher.start()
        self.addCleanup(self._patcher.stop)
        os.environ["T_ALICE_USER"] = "alice@shop.test"
        os.environ["T_ALICE_PASS"] = "Sup3rS3cret-Passw0rd!"
        os.environ["T_COOKIE"] = "session=abc123token; role=user"
        os.environ["T_TOKEN"] = "tok-en-abcdef123"

    def tearDown(self):
        redactor.clear()
        for k in ("T_ALICE_USER", "T_ALICE_PASS", "T_COOKIE", "T_TOKEN"):
            os.environ.pop(k, None)


class TestFormLogin(Base):
    def test_success_with_token_extraction(self):
        FakeScopedSession.queue = [
            FakeResponse(200, text="{}", body={"authentication":
                                               {"token": "tok-en-abcdef123"}}),
            FakeResponse(200, text='{"user":"alice"}'),
        ]
        sessions = make_manager([FORM])
        meta = sessions.login("alice")
        self.assertTrue(meta.verified)
        self.assertIn("verified", meta.note)
        sess = sessions.get_session("alice")
        self.assertEqual(sess.headers["Authorization"],
                         "Bearer tok-en-abcdef123")
        # first call was the form POST with the credentials as fields
        post = sess.calls[0]
        self.assertEqual(post["method"], "POST")
        self.assertEqual(post["data"]["email"], "alice@shop.test")
        self.assertEqual(post["data"]["password"], "Sup3rS3cret-Passw0rd!")

    def test_verify_failure_leaves_no_session(self):
        FakeScopedSession.queue = [
            FakeResponse(200, text="{}"),
            FakeResponse(200, text='{"user":"someone-else"}'),
        ]
        sessions = make_manager([FORM])
        with self.assertRaises(ToolError) as cm:
            sessions.login("alice")
        self.assertIn("FAILED", str(cm.exception))
        self.assertFalse(sessions.is_logged_in("alice"))
        self.assertEqual(sessions.status()[0]["logged_in"], False)

    def test_http_error_leaves_no_session(self):
        FakeScopedSession.queue = [FakeResponse(401, text="unauthorized")]
        sessions = make_manager([FORM])
        with self.assertRaises(ToolError) as cm:
            sessions.login("alice")
        self.assertIn("401", str(cm.exception))
        self.assertFalse(sessions.is_logged_in("alice"))

    def test_missing_env_names_the_variable_not_a_value(self):
        os.environ.pop("T_ALICE_PASS")
        sessions = make_manager([FORM])
        with self.assertRaises(ToolError) as cm:
            sessions.login("alice")
        self.assertIn("T_ALICE_PASS", str(cm.exception))

    def test_network_error_becomes_tool_error(self):
        FakeScopedSession.raise_on_request = ConnectionError("boom")
        sessions = make_manager([FORM])
        with self.assertRaises(ToolError):
            sessions.login("alice")
        self.assertFalse(sessions.is_logged_in("alice"))


class TestStaticKinds(Base):
    def test_cookie_kind_sets_cookie_header_and_registers_secret(self):
        sessions = make_manager([IdentityConfig(name="s", kind="cookie",
                                                cookie_env="T_COOKIE")])
        meta = sessions.login("s")
        self.assertIn("NOT proven", meta.note)   # honest: no verify_url
        sess = sessions.get_session("s")
        self.assertEqual(sess.headers["Cookie"], "session=abc123token; role=user")
        self.assertGreaterEqual(redactor.count, 1)

    def test_bearer_kind(self):
        sessions = make_manager([IdentityConfig(name="b", kind="bearer",
                                                token_env="T_TOKEN")])
        sessions.login("b")
        self.assertEqual(sessions.get_session("b").headers["Authorization"],
                         "Bearer tok-en-abcdef123")

    def test_apikey_default_and_custom_header(self):
        sessions = make_manager([
            IdentityConfig(name="k1", kind="apikey", token_env="T_TOKEN"),
            IdentityConfig(name="k2", kind="apikey", token_env="T_TOKEN",
                           header_name="X-Auth"),
        ])
        sessions.login("k1")
        sessions.login("k2")
        self.assertEqual(sessions.get_session("k1").headers["X-API-Key"],
                         "tok-en-abcdef123")
        self.assertEqual(sessions.get_session("k2").headers["X-Auth"],
                         "tok-en-abcdef123")

    def test_bearer_token_from_env_never_in_status(self):
        sessions = make_manager([IdentityConfig(name="b", kind="bearer",
                                                token_env="T_TOKEN")])
        sessions.login("b")
        blob = json.dumps(sessions.status())
        self.assertNotIn("tok-en-abcdef123", blob)


class TestLifecycle(Base):
    def test_get_session_before_login_is_tool_error(self):
        sessions = make_manager([FORM])
        with self.assertRaises(ToolError) as cm:
            sessions.get_session("alice")
        self.assertIn("session_login first", str(cm.exception))

    def test_unknown_identity_lists_configured(self):
        sessions = make_manager([FORM])
        with self.assertRaises(ToolError) as cm:
            sessions.login("mallory")
        self.assertIn("alice", str(cm.exception))

    def test_logout_clears_session(self):
        FakeScopedSession.queue = [FakeResponse(200, text="ok"),
                                   FakeResponse(200, text="alice")]
        sessions = make_manager([FORM])
        sessions.login("alice")
        self.assertTrue(sessions.logout("alice"))
        with self.assertRaises(ToolError):
            sessions.get_session("alice")
        self.assertFalse(sessions.logout("alice"))

    def test_relogin_starts_from_clean_session(self):
        FakeScopedSession.queue = [FakeResponse(200, text="a"),
                                   FakeResponse(200, text="alice"),
                                   FakeResponse(200, text="b"),
                                   FakeResponse(200, text="alice")]
        sessions = make_manager([FORM])
        sessions.login("alice")
        first_sess = sessions.get_session("alice")
        second = sessions.login("alice")
        second_sess = sessions.get_session("alice")
        self.assertIsNot(first_sess, second_sess)  # fresh jar on re-login
        self.assertTrue(second.verified)


class TestScopeAndAudit(Base):
    def test_scope_violation_aborts_and_is_audited(self):
        audit = AuditLog(Path(tempfile.mkdtemp()) / "audit.jsonl")
        FakeScopedSession.raise_on_request = ScopeViolation("login_url out of scope")
        sessions = make_manager([FORM], audit=audit)
        with self.assertRaises(ScopeViolation):
            sessions.login("alice")
        self.assertFalse(sessions.is_logged_in("alice"))
        raw = audit.path.read_text(encoding="utf-8")
        self.assertIn("session_login_denied", raw)
        ok, msg = verify_chain(audit.path)
        self.assertTrue(ok, msg)

    def test_audit_contains_no_secret_values(self):
        audit = AuditLog(Path(tempfile.mkdtemp()) / "audit.jsonl")
        FakeScopedSession.queue = [
            FakeResponse(200, text="{}",
                         body={"authentication": {"token": "tok-en-abcdef123"}}),
            FakeResponse(200, text="alice"),
        ]
        sessions = make_manager([FORM], audit=audit)
        sessions.login("alice")
        # failure path too: echo the password in an error body
        FakeScopedSession.queue = [FakeResponse(
            401, text="bad password Sup3rS3cret-Passw0rd!")]
        with self.assertRaises(ToolError):
            sessions.login("alice")
        raw = audit.path.read_text(encoding="utf-8")
        self.assertNotIn("Sup3rS3cret-Passw0rd!", raw)
        self.assertNotIn("tok-en-abcdef123", raw)
        ok, _ = verify_chain(audit.path)
        self.assertTrue(ok)


class TestSessionTools(Base):
    def _tools(self, identities, audit=None):
        from redteam.tools.session import (SessionLoginTool, SessionLogoutTool,
                                           SessionStatusTool)
        sessions = make_manager(identities, audit=audit)
        return sessions, (SessionLoginTool(sessions),
                          SessionStatusTool(sessions),
                          SessionLogoutTool(sessions))

    def test_login_status_logout_roundtrip(self):
        FakeScopedSession.queue = [FakeResponse(200, text="ok"),
                                   FakeResponse(200, text="alice")]
        _, (login_t, status_t, logout_t) = self._tools([FORM])
        res = login_t.run({"identity": "alice"})
        self.assertTrue(res.ok)
        self.assertIn("verified=True", res.summary)
        self.assertNotIn("Sup3rS3cret", json.dumps(res.data))

        res = status_t.run({})
        rows = res.data["identities"]
        self.assertEqual(rows[0]["identity"], "alice")
        self.assertTrue(rows[0]["logged_in"])

        res = logout_t.run({"identity": "alice"})
        self.assertTrue(res.data["ended"])

    def test_status_without_logins(self):
        _, (_, status_t, _) = self._tools([FORM])
        res = status_t.run({})
        self.assertIn("0 logged in", res.summary)
        self.assertFalse(res.data["identities"][0]["logged_in"])

    def test_logout_all(self):
        FakeScopedSession.queue = [FakeResponse(200, text="x"),
                                   FakeResponse(200, text="alice")]
        _, (login_t, _, logout_t) = self._tools([FORM])
        login_t.run({"identity": "alice"})
        res = logout_t.run({})
        self.assertEqual(res.data["ended"], 1)

    def test_session_tools_registered_in_orchestrator(self):
        from dataclasses import replace

        from redteam.config import load_config
        from redteam.orchestrator import Orchestrator

        root = Path(__file__).resolve().parent.parent
        cfg = load_config(root / "config.example.yaml")
        tmp = Path(tempfile.mkdtemp())
        cfg = replace(cfg, safety=replace(
            cfg.safety, artifacts_dir=str(tmp / "art"),
            cassette_dir=str(tmp / "cass"), runner="local"))
        orch = Orchestrator(cfg)
        for tool_name in ("session_login", "session_status", "session_logout"):
            self.assertIsNotNone(orch.registry.get(tool_name), tool_name)


class TestBearerExtraction(Base):
    def test_various_token_shapes(self):
        self.assertEqual(
            _extract_bearer(FakeResponse(body={"authentication": {"token": "t1"}})),
            "t1")
        self.assertEqual(_extract_bearer(FakeResponse(body={"token": "t2"})), "t2")
        self.assertEqual(_extract_bearer(FakeResponse(body={"access_token": "t3"})),
                         "t3")
        self.assertEqual(_extract_bearer(FakeResponse(body={"user": "x"})), "")
        self.assertEqual(_extract_bearer(FakeResponse(text="html")), "")


class TestSessionCookieHygiene(Base):
    """Cookie material the target hands us is live credential material: it is
    registered for redaction, and a pre-auth cookie can be replayed into the
    login request (the fixation probe's building block)."""

    def test_login_registers_cookies_from_the_target(self):
        FakeScopedSession.queue = [
            FakeResponse(200, text="{}",
                         set_cookies={"session": "SESS-VALUE-123"}),
            FakeResponse(200, text='{"user":"alice"}'),
        ]
        sessions = make_manager([FORM])
        sessions.login("alice")
        self.assertEqual(redactor.scrub("SESS-VALUE-123"), "[REDACTED]")

    def test_preflight_cookie_is_sent_and_registered(self):
        FakeScopedSession.queue = [
            FakeResponse(200, text="{}"),
            FakeResponse(200, text='{"user":"alice"}'),
        ]
        sessions = make_manager([FORM])
        sessions.login("alice", preflight_cookie="pre_auth=PRE-VALUE-999")
        inst = FakeScopedSession.instances[-1]
        self.assertEqual(inst.headers.get("Cookie"), "pre_auth=PRE-VALUE-999")
        self.assertEqual(redactor.scrub("PRE-VALUE-999"), "[REDACTED]")

    def test_cookies_accessor_merges_jar_and_header(self):
        FakeScopedSession.queue = [
            FakeResponse(200, text="{}",
                         set_cookies={"session": "SESS-VALUE-123"}),
            FakeResponse(200, text='{"user":"alice"}'),
        ]
        sessions = make_manager([FORM])
        sessions.login("alice", preflight_cookie="pre_auth=PRE-VALUE-999")
        jar = sessions.cookies("alice")
        self.assertEqual(jar["session"], "SESS-VALUE-123")
        self.assertEqual(jar["pre_auth"], "PRE-VALUE-999")

    def test_config_rejects_non_http_logout_url(self):
        from redteam.config import _identity
        with self.assertRaises(ValueError):
            _identity({"name": "x", "kind": "cookie", "cookie_env": "T_COOKIE",
                       "logout_url": "ftp://nope"})
        ident = _identity({"name": "x", "kind": "cookie",
                           "cookie_env": "T_COOKIE",
                           "logout_url": "https://shop.test/logout"})
        self.assertEqual(ident.logout_url, "https://shop.test/logout")


if __name__ == "__main__":
    unittest.main()
