"""Phase 2.3 — session lifecycle: cookie flags, logout invalidation, fixation.

Pure verdict-function tests plus tool-level probes against scripted fakes
(zero network): the logout replay and the anonymous fixation capture are
patched at redteam.tools.session_check.ScopedSession; the login itself at
redteam.auth.ScopedSession (reusing test_session's fake).
"""

from __future__ import annotations

import os
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest import mock

from redteam.auth import SessionManager
from redteam.config import IdentityConfig, load_config
from redteam.redact import redactor
from redteam.tools.base import ToolError
from redteam.tools.session_check import (SessionCheckTool, cookie_flag_verdict,
                                         fixation_verdict, logout_verdict)

from test_phase1 import make_guard
from test_session import FakeScopedSession as AuthFake
from test_session import FakeResponse as AuthResponse

NOW = 1_700_000_000.0
TOMORROW = NOW + 86400
FAR_FUTURE = NOW + 30 * 86400


def cookie(name="session", httponly=True, secure=True, samesite="Lax",
           expires=TOMORROW, **extra):
    base = {"name": name, "value": "v" * 8, "domain": "shop.test",
            "path": "/", "httponly": httponly, "secure": secure,
            "samesite": samesite, "expires": expires}
    base.update(extra)
    return base


class TestCookieFlagVerdict(unittest.TestCase):
    def test_missing_httponly_is_confirmed(self):
        v = cookie_flag_verdict([cookie(httponly=False)], https=True, now=NOW)
        self.assertEqual(v["verdict"], "confirmed")
        self.assertEqual(v["cwe"], "CWE-1004")
        self.assertIn("HttpOnly", v["reason"])

    def test_missing_secure_over_https_is_confirmed(self):
        v = cookie_flag_verdict([cookie(secure=False)], https=True, now=NOW)
        self.assertEqual(v["verdict"], "confirmed")
        self.assertIn("Secure", v["reason"])

    def test_missing_secure_on_http_not_flagged(self):
        v = cookie_flag_verdict([cookie(samesite="Lax")], https=False, now=NOW)
        self.assertEqual(v["verdict"], "no_issue")

    def test_missing_samesite_is_suspected(self):
        v = cookie_flag_verdict([cookie(samesite="")], https=True, now=NOW)
        self.assertEqual(v["verdict"], "suspected")
        self.assertEqual(v["cwe"], "CWE-1275")

    def test_long_lifetime_is_suspected(self):
        v = cookie_flag_verdict([cookie(expires=FAR_FUTURE)], https=True,
                                now=NOW)
        self.assertEqual(v["verdict"], "suspected")
        self.assertIn("CWE-613", v["reason"])

    def test_clean_cookie_is_no_issue(self):
        v = cookie_flag_verdict([cookie()], https=True, now=NOW)
        self.assertEqual(v["verdict"], "no_issue")

    def test_no_cookies_is_inconclusive(self):
        v = cookie_flag_verdict([], https=True, now=NOW)
        self.assertEqual(v["verdict"], "inconclusive")

    def test_non_session_cookie_only_is_inconclusive(self):
        v = cookie_flag_verdict([cookie(name="lang")], https=True, now=NOW)
        self.assertEqual(v["verdict"], "inconclusive")


class TestLogoutVerdict(unittest.TestCase):
    def test_still_valid_after_logout_is_confirmed(self):
        v = logout_verdict(200, 200, 200)
        self.assertEqual(v["verdict"], "confirmed")
        self.assertEqual(v["cwe"], "CWE-613")

    def test_invalidated_is_no_issue(self):
        v = logout_verdict(200, 200, 401)
        self.assertEqual(v["verdict"], "no_issue")

    def test_logout_rejected_is_inconclusive(self):
        v = logout_verdict(200, 403, 401)
        self.assertEqual(v["verdict"], "inconclusive")
        self.assertIn("CSRF", v["reason"])

    def test_protected_url_unreadable_is_inconclusive(self):
        v = logout_verdict(401, 200, 401)
        self.assertEqual(v["verdict"], "inconclusive")

    def test_logout_server_error_is_inconclusive(self):
        v = logout_verdict(200, 502, 200)
        self.assertEqual(v["verdict"], "inconclusive")


class TestFixationVerdict(unittest.TestCase):
    def test_unchanged_identifier_is_confirmed(self):
        v = fixation_verdict({"session": "PRE123"}, {"session": "PRE123"})
        self.assertEqual(v["verdict"], "confirmed")
        self.assertEqual(v["cwe"], "CWE-384")
        self.assertEqual(v["unchanged"], ["session"])

    def test_rotated_identifier_is_no_issue(self):
        v = fixation_verdict({"session": "PRE123"},
                             {"session": "ROTATED99"})
        self.assertEqual(v["verdict"], "no_issue")

    def test_no_pre_auth_cookie_is_inconclusive(self):
        v = fixation_verdict({}, {})
        self.assertEqual(v["verdict"], "inconclusive")

    def test_unrelated_cookie_cannot_fake_a_positive(self):
        # locale persists through login, but it is not a session id
        v = fixation_verdict({"lang": "en", "session": "PRE123"},
                             {"lang": "en", "session": "ROTATED99"})
        self.assertEqual(v["verdict"], "no_issue")


# ---- tool-level probes ------------------------------------------------------

IDENT = IdentityConfig(
    name="alice", kind="form",
    login_url="https://shop.test/rest/user/login",
    username_env="T_SC_USER", password_env="T_SC_PASS",
    logout_url="https://shop.test/logout",
)
IDENT_NO_LOGOUT = IdentityConfig(
    name="carol", kind="cookie", cookie_env="T_SC_COOKIE",
)


class FakeJarSession:
    """A logged-in identity's session with a scripted jar + responses."""

    def __init__(self, responses=None, jar=None, details=None,
                 header=""):
        self.responses = list(responses or [])
        self.jar = dict(jar or {})
        self._details = list(details if details is not None
                             else [cookie(name=n, value=v)
                                   for n, v in self.jar.items()])
        self.header = header
        self.calls = []

    def get(self, url, **kwargs):
        self.calls.append(("GET", url))
        return self.responses.pop(0) if self.responses else AuthResponse()

    def request(self, method, url, **kwargs):
        self.calls.append((method, url))
        return self.responses.pop(0) if self.responses else AuthResponse()

    def cookies(self):
        return dict(self.jar)

    def cookie_header(self):
        return self.header

    def cookie_details(self):
        return [dict(c) for c in self._details]


class FakeAnonSession:
    """Anonymous ScopedSession: serves scripted responses + jar content."""

    queue: list = []
    instances: list = []

    def __init__(self, guard=None, **kwargs):
        self.calls = []
        self.headers: dict[str, str] = {}
        self.jar: dict[str, str] = {}
        type(self).instances.append(self)

    def set_default_header(self, name, value):
        self.headers[name] = value

    def get(self, url, **kwargs):
        self.calls.append(("GET", url))
        resp = self.fake_request("GET", url)
        self.jar.update(getattr(resp, "set_cookies", {}) or {})
        return resp

    def request(self, method, url, **kwargs):
        self.calls.append((method, url))
        return self.fake_request(method, url)

    def fake_request(self, method, url):
        return FakeAnonSession.queue.pop(0) if FakeAnonSession.queue \
            else AuthResponse()

    def cookies(self):
        return dict(self.jar)


def sessions_with(*idents, **injected) -> SessionManager:
    mgr = SessionManager(list(idents), make_guard())
    for name, fake in injected.items():
        mgr._sessions[name] = fake
    return mgr


class ToolBase(unittest.TestCase):
    def setUp(self):
        redactor.clear()
        AuthFake.queue = []
        AuthFake.instances = []
        AuthFake.raise_on_request = None
        FakeAnonSession.queue = []
        FakeAnonSession.instances = []
        self.p1 = mock.patch("redteam.auth.ScopedSession", AuthFake)
        self.p2 = mock.patch("redteam.tools.session_check.ScopedSession",
                             FakeAnonSession)
        self.p1.start()
        self.p2.start()
        self.addCleanup(self.p1.stop)
        self.addCleanup(self.p2.stop)
        os.environ["T_SC_USER"] = "alice@shop.test"
        os.environ["T_SC_PASS"] = "Sup3rS3cret-Passw0rd!"
        os.environ["T_SC_COOKIE"] = "session=static1234"

    def tearDown(self):
        redactor.clear()
        for key in ("T_SC_USER", "T_SC_PASS", "T_SC_COOKIE"):
            os.environ.pop(key, None)


class TestCookieFlagsTool(ToolBase):
    def test_flags_missing_httponly_confirmed(self):
        fake = FakeJarSession(details=[cookie(httponly=False)])
        mgr = sessions_with(IDENT, alice=fake)
        res = SessionCheckTool(mgr).run({"check": "cookie_flags",
                                         "identity": "alice",
                                         "url": "https://shop.test/whoami"})
        self.assertEqual(res.data["verdict"], "confirmed")
        self.assertIn("status", res.data["evidence"])
        self.assertIn("httponly=False", res.data["evidence"])

    def test_clean_cookie_no_issue(self):
        fake = FakeJarSession(details=[cookie()])
        mgr = sessions_with(IDENT, alice=fake)
        res = SessionCheckTool(mgr).run({"check": "cookie_flags",
                                         "identity": "alice",
                                         "url": "https://shop.test/whoami"})
        self.assertEqual(res.data["verdict"], "no_issue")
        self.assertIn("do NOT record", res.data["recommendation"])

    def test_needs_url_or_verify_url(self):
        mgr = sessions_with(IDENT_NO_LOGOUT, carol=FakeJarSession())
        with self.assertRaises(ToolError):
            SessionCheckTool(mgr).run({"check": "cookie_flags",
                                       "identity": "carol"})

    def test_bad_check_rejected(self):
        mgr = sessions_with(IDENT, alice=FakeJarSession())
        with self.assertRaises(ToolError):
            SessionCheckTool(mgr).run({"check": "nuke", "identity": "alice"})


class TestLogoutTool(ToolBase):
    def test_still_valid_after_logout_is_confirmed(self):
        fake = FakeJarSession(
            responses=[AuthResponse(200, "secret area"),
                       AuthResponse(200, "bye")],
            jar={"session": "SESS-VALUE-1234"})
        fresh = FakeAnonSession
        fresh.queue = [AuthResponse(200, "secret area")]
        mgr = sessions_with(IDENT, alice=fake)
        res = SessionCheckTool(mgr).run({"check": "logout",
                                         "identity": "alice",
                                         "url": "https://shop.test/secret"})
        self.assertEqual(res.data["verdict"], "confirmed")
        self.assertIn("session", res.data["note"])
        # the replay used the captured cookie on a fresh session
        self.assertEqual(fresh.instances[-1].calls, [("GET",
                                                      "https://shop.test/secret")])
        self.assertIn("session_login", res.data["note"])

    def test_invalidated_after_logout_is_no_issue(self):
        fake = FakeJarSession(
            responses=[AuthResponse(200, "secret area"),
                       AuthResponse(200, "bye")],
            jar={"session": "SESS-VALUE-1234"})
        FakeAnonSession.queue = [AuthResponse(401, "denied")]
        mgr = sessions_with(IDENT, alice=fake)
        res = SessionCheckTool(mgr).run({"check": "logout",
                                         "identity": "alice",
                                         "url": "https://shop.test/secret"})
        self.assertEqual(res.data["verdict"], "no_issue")

    def test_logout_rejected_is_inconclusive(self):
        fake = FakeJarSession(
            responses=[AuthResponse(200, "secret area"),
                       AuthResponse(403, "csrf")],
            jar={"session": "SESS-VALUE-1234"})
        mgr = sessions_with(IDENT, alice=fake)
        res = SessionCheckTool(mgr).run({"check": "logout",
                                         "identity": "alice",
                                         "url": "https://shop.test/secret"})
        self.assertEqual(res.data["verdict"], "inconclusive")

    def test_unreadable_protected_url_is_inconclusive(self):
        fake = FakeJarSession(responses=[AuthResponse(401, "denied")],
                              jar={"session": "SESS-VALUE-1234"})
        mgr = sessions_with(IDENT, alice=fake)
        res = SessionCheckTool(mgr).run({"check": "logout",
                                         "identity": "alice",
                                         "url": "https://shop.test/secret"})
        self.assertEqual(res.data["verdict"], "inconclusive")

    def test_no_logout_url_is_inconclusive_without_network(self):
        fake = FakeJarSession()
        mgr = sessions_with(IDENT_NO_LOGOUT, carol=fake)
        res = SessionCheckTool(mgr).run({"check": "logout",
                                         "identity": "carol",
                                         "url": "https://shop.test/x"})
        self.assertEqual(res.data["verdict"], "inconclusive")
        self.assertEqual(fake.calls, [])  # nothing was sent

    def test_captured_cookies_are_redacted_in_evidence(self):
        fake = FakeJarSession(
            responses=[AuthResponse(200, "ok"), AuthResponse(200, "bye")],
            jar={"session": "SESS-VALUE-1234"})
        FakeAnonSession.queue = [AuthResponse(401, "denied")]
        mgr = sessions_with(IDENT, alice=fake)
        res = SessionCheckTool(mgr).run({"check": "logout",
                                         "identity": "alice",
                                         "url": "https://shop.test/secret"})
        self.assertNotIn("SESS-VALUE-1234", res.data["evidence"])
        self.assertIn("[REDACTED]", res.data["evidence"])


class TestFixationTool(ToolBase):
    def _login_queue(self, set_cookies=None):
        AuthFake.queue = [AuthResponse(200, "{}", set_cookies=set_cookies)]

    def test_unchanged_identifier_is_confirmed(self):
        FakeAnonSession.queue = [
            AuthResponse(200, "login page", set_cookies={"session": "PRE123456"})]
        self._login_queue()  # server keeps the pre-auth id
        mgr = sessions_with(IDENT)
        res = SessionCheckTool(mgr).run({"check": "fixation",
                                         "identity": "alice",
                                         "url": "https://shop.test/login"})
        self.assertEqual(res.data["verdict"], "confirmed")
        self.assertEqual(res.data["cwe"], "CWE-384")
        # the pre-auth cookie really was sent with the login POST
        self.assertEqual(AuthFake.instances[-1].headers["Cookie"],
                         "session=PRE123456")

    def test_rotated_identifier_is_no_issue(self):
        FakeAnonSession.queue = [
            AuthResponse(200, "login page", set_cookies={"session": "PRE123456"})]
        self._login_queue(set_cookies={"session": "ROTATED9999"})
        mgr = sessions_with(IDENT)
        res = SessionCheckTool(mgr).run({"check": "fixation",
                                         "identity": "alice",
                                         "url": "https://shop.test/login"})
        self.assertEqual(res.data["verdict"], "no_issue")

    def test_no_pre_auth_cookie_short_circuits(self):
        mgr = sessions_with(IDENT)
        res = SessionCheckTool(mgr).run({"check": "fixation",
                                         "identity": "alice",
                                         "url": "https://shop.test/login"})
        self.assertEqual(res.data["verdict"], "inconclusive")
        self.assertEqual(AuthFake.instances, [])  # login was never attempted


class TestWiring(ToolBase):
    def test_registered_in_orchestrator(self):
        from redteam.orchestrator import ACTIVE_TOOLS, Orchestrator
        root = Path(__file__).resolve().parent.parent
        cfg = load_config(root / "config.example.yaml")
        tmp = Path(tempfile.mkdtemp())
        cfg = replace(cfg, safety=replace(
            cfg.safety, artifacts_dir=str(tmp / "art"),
            cassette_dir=str(tmp / "cass"), runner="local"))
        orch = Orchestrator(cfg)
        self.assertIsNotNone(orch.registry.get("session_check"))
        self.assertIn("session_check", ACTIVE_TOOLS)
        self.assertIn("account_enum", ACTIVE_TOOLS)


if __name__ == "__main__":
    unittest.main()
