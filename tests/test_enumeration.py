"""Phase 2.3 — account enumeration via response diffing (CWE-204).

Pure verdict-function tests plus tool-level tests with a scripted fake
transport (zero network). The two probes must use a locally generated
wrong password that never comes from config, and the known account name
must be redacted from evidence.
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
from redteam.tools.enumeration import (AccountEnumTool, enum_verdict,
                                       generate_fake_username, normalize_body)

from test_phase1 import make_guard

REAL_USER = "alice@shop.test"
REAL_PASS = "Sup3rS3cret-Passw0rd!"


class FakeResponse:
    def __init__(self, status=200, text=""):
        self.status_code = status
        self.text = text


class FakeScopedSession:
    queue: list[FakeResponse] = []
    calls: list[dict] = []

    def __init__(self, guard=None, **kwargs):
        pass

    def request(self, method, url, headers=None, data=None, json=None,
                timeout=None, allow_redirects=True, verify=None):
        FakeScopedSession.calls.append({"method": method, "url": url,
                                        "data": data})
        return FakeScopedSession.queue.pop(0) if FakeScopedSession.queue \
            else FakeResponse(500, "no scripted response")

    def get(self, url, **kwargs):
        return self.request("GET", url, **kwargs)


FORM = IdentityConfig(
    name="alice", kind="form",
    login_url="https://shop.test/rest/user/login",
    username_env="T_ENUM_USER", password_env="T_ENUM_PASS",
)
NO_USERNAME = IdentityConfig(name="bob", kind="cookie",
                             cookie_env="T_ENUM_COOKIE")


class Base(unittest.TestCase):
    def setUp(self):
        redactor.clear()
        FakeScopedSession.queue = []
        FakeScopedSession.calls = []
        self.patcher = mock.patch("redteam.tools.enumeration.ScopedSession",
                                  FakeScopedSession)
        self.patcher.start()
        self.addCleanup(self.patcher.stop)
        os.environ["T_ENUM_USER"] = REAL_USER
        os.environ["T_ENUM_PASS"] = REAL_PASS
        os.environ["T_ENUM_COOKIE"] = "session=abc123token"

    def tearDown(self):
        redactor.clear()
        for key in ("T_ENUM_USER", "T_ENUM_PASS", "T_ENUM_COOKIE"):
            os.environ.pop(key, None)

    def tool(self, identities=(FORM,)) -> AccountEnumTool:
        return AccountEnumTool(SessionManager(list(identities), make_guard()))


class TestEnumVerdict(unittest.TestCase):
    def test_identical_responses_are_no_issue(self):
        body = "Invalid credentials"
        v = enum_verdict(401, 401, body, body, [REAL_USER, "x"])
        self.assertEqual(v["verdict"], "no_issue")
        self.assertTrue(v["bodies_identical"])

    def test_echo_only_difference_is_no_issue(self):
        # the server merely echoes the submitted username — normalized away
        v = enum_verdict(
            401, 401,
            "No account for alice@shop.test",
            "No account for rt-enum-abc@invalid.example",
            [REAL_USER, "rt-enum-abc@invalid.example"])
        self.assertEqual(v["verdict"], "no_issue")

    def test_explicit_existence_message_is_confirmed(self):
        v = enum_verdict(
            200, 200,
            "Invalid password for this account",
            "No such user",
            [REAL_USER, "rt-enum-x"])
        self.assertEqual(v["verdict"], "confirmed")
        self.assertEqual(v["cwe"], "CWE-204")
        self.assertIn("no such user", v["negative_markers_in_fake"])

    def test_positive_marker_asymmetry_is_confirmed(self):
        v = enum_verdict(200, 200, "Incorrect password", "Try again later",
                         [REAL_USER, "rt-enum-x"])
        self.assertEqual(v["verdict"], "confirmed")
        self.assertIn("incorrect password", v["positive_markers_in_real"])

    def test_status_difference_is_suspected(self):
        v = enum_verdict(200, 404, "OK", "nope", [REAL_USER, "rt-enum-x"])
        self.assertEqual(v["verdict"], "suspected")
        self.assertTrue(v["status_differs"])

    def test_body_difference_without_markers_is_suspected(self):
        v = enum_verdict(200, 200, "Welcome back", "Try later",
                         [REAL_USER, "rt-enum-x"])
        self.assertEqual(v["verdict"], "suspected")

    def test_server_error_is_inconclusive(self):
        v = enum_verdict(500, 401, "", "x", [REAL_USER, "rt-enum-x"])
        self.assertEqual(v["verdict"], "inconclusive")


class TestHelpers(unittest.TestCase):
    def test_fake_username_emailish(self):
        fake = generate_fake_username("a@b.c", "email")
        self.assertIn("@", fake)
        self.assertNotEqual(fake, "a@b.c")

    def test_fake_username_plain_field(self):
        self.assertNotIn("@", generate_fake_username("alice", "username"))

    def test_fake_username_is_random_each_call(self):
        self.assertNotEqual(generate_fake_username("a@b", "email"),
                            generate_fake_username("a@b", "email"))

    def test_normalize_masks_and_collapses(self):
        out = normalize_body("  User   ALICE@shop.test logged IN ",
                             [REAL_USER])
        self.assertEqual(out, "user <user> logged in")


class TestEnumTool(Base):
    def test_confirmed_probe_uses_wrong_password_not_config(self):
        FakeScopedSession.queue = [
            FakeResponse(200, "Invalid password"),
            FakeResponse(200, "No such user"),
        ]
        res = self.tool().run({"url": "https://shop.test/rest/user/login",
                               "identity": "alice"})
        self.assertEqual(res.data["verdict"], "confirmed")
        self.assertIn("CWE-204", res.data["recommendation"])
        real, fake = FakeScopedSession.calls
        self.assertEqual(real["method"], "POST")
        self.assertEqual(real["data"]["email"], REAL_USER)
        self.assertNotEqual(real["data"]["password"], REAL_PASS)
        # both probes must use the SAME wrong password (only the name varies)
        self.assertEqual(real["data"]["password"], fake["data"]["password"])
        self.assertNotEqual(fake["data"]["email"], REAL_USER)
        # evidence carries the request/response pair required for confirmed
        self.assertIn("status", res.data["evidence"])
        self.assertIn("response", res.data["evidence"].lower())

    def test_username_is_redacted_from_evidence(self):
        FakeScopedSession.queue = [
            FakeResponse(200, "Invalid password"),
            FakeResponse(200, "No such user"),
        ]
        res = self.tool().run({"url": "https://shop.test/x",
                               "identity": "alice"})
        self.assertNotIn(REAL_USER, res.data["evidence"])
        self.assertIn("[REDACTED]", res.data["evidence"])

    def test_identical_responses_report_no_issue(self):
        FakeScopedSession.queue = [
            FakeResponse(401, "Invalid credentials"),
            FakeResponse(401, "Invalid credentials"),
        ]
        res = self.tool().run({"url": "https://shop.test/x",
                               "identity": "alice"})
        self.assertEqual(res.data["verdict"], "no_issue")
        self.assertIn("do NOT record", res.data["recommendation"])

    def test_missing_env_names_the_variable(self):
        os.environ.pop("T_ENUM_USER")
        with self.assertRaises(ToolError) as cm:
            self.tool().run({"url": "https://shop.test/x", "identity": "alice"})
        self.assertIn("T_ENUM_USER", str(cm.exception))
        self.assertEqual(FakeScopedSession.calls, [])  # no probe sent

    def test_identity_without_username_env_is_rejected(self):
        with self.assertRaises(ToolError):
            self.tool((NO_USERNAME,)).run(
                {"url": "https://shop.test/x", "identity": "bob"})
        self.assertEqual(FakeScopedSession.calls, [])

    def test_unknown_identity_is_rejected(self):
        with self.assertRaises(ToolError):
            self.tool().run({"url": "https://shop.test/x",
                             "identity": "nobody"})
        self.assertEqual(FakeScopedSession.calls, [])

    def test_get_method_builds_query(self):
        FakeScopedSession.queue = [FakeResponse(200, "same"),
                                   FakeResponse(200, "same")]
        self.tool().run({"url": "https://shop.test/forgot",
                         "identity": "alice", "method": "GET"})
        call = FakeScopedSession.calls[0]
        self.assertEqual(call["method"], "GET")
        self.assertIn("email=", call["url"])

    def test_write_methods_rejected(self):
        with self.assertRaises(ToolError):
            self.tool().run({"url": "https://shop.test/x",
                             "identity": "alice", "method": "DELETE"})

    def test_registered_in_orchestrator(self):
        root = Path(__file__).resolve().parent.parent
        cfg = load_config(root / "config.example.yaml")
        tmp = Path(tempfile.mkdtemp())
        cfg = replace(cfg, safety=replace(
            cfg.safety, artifacts_dir=str(tmp / "art"),
            cassette_dir=str(tmp / "cass"), runner="local"))
        from redteam.orchestrator import Orchestrator
        self.assertIsNotNone(Orchestrator(cfg).registry.get("account_enum"))


if __name__ == "__main__":
    unittest.main()
