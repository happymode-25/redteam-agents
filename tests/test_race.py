"""Phase 2.4 — bounded race-condition tester (catalog section 11).

Pure burst_verdict tables plus tool-level tests against a scripted fake
transport (zero network): worker seeding with identity credentials,
count/method caps, the disabled-by-default gate, evidence redaction, and
ScopeViolation propagating out of the thread pool (stage abort invariant).
"""

from __future__ import annotations

import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest import mock

import requests

from redteam.auth import SessionManager
from redteam.config import IdentityConfig, load_config
from redteam.redact import redactor
from redteam.scope import ScopeViolation
from redteam.tools.base import ToolError
from redteam.tools.race import MAX_BURST, RaceBurstTool, burst_verdict

from test_phase1 import make_guard

ALLOWED = ("shop.test",)
URL = "https://shop.test/api/redeem"


def outcome(i, status=None, ok=False, sha=None, error=None, body=""):
    return {"index": i, "status": status, "ok": ok,
            "sha": sha or f"sha{i}", "error": error, "body": body}


class TestBurstVerdict(unittest.TestCase):
    def test_all_transport_errors_inconclusive(self):
        v = burst_verdict([outcome(i, error="connection refused")
                           for i in range(3)])
        self.assertEqual(v["verdict"], "inconclusive")
        self.assertIn("transport", v["reason"])

    def test_no_success_inconclusive(self):
        v = burst_verdict([outcome(0, 401, sha="a"),
                           outcome(1, 403, sha="b")])
        self.assertEqual(v["verdict"], "inconclusive")
        self.assertIn("none of the 2", v["reason"])

    def test_more_successes_than_invariant_is_confirmed(self):
        v = burst_verdict([outcome(0, 200, ok=True, sha="a"),
                           outcome(1, 200, ok=True, sha="a"),
                           outcome(2, 409, sha="b")],
                          expect_success_max=1)
        self.assertEqual(v["verdict"], "confirmed")
        self.assertEqual(v["cwe"], "CWE-362")
        self.assertEqual(v["success_count"], 2)
        self.assertIn("not serialized", v["reason"])

    def test_zero_allowed_and_one_success_confirmed(self):
        v = burst_verdict([outcome(0, 200, ok=True)], expect_success_max=0)
        self.assertEqual(v["verdict"], "confirmed")

    def test_server_error_under_concurrency_suspected(self):
        v = burst_verdict([outcome(0, 200, ok=True, sha="a"),
                           outcome(1, 500, sha="b"),
                           outcome(2, 500, sha="b")],
                          expect_success_max=1)
        self.assertEqual(v["verdict"], "suspected")
        self.assertEqual(v["unexpected_statuses"], [500])
        self.assertIn("concurrency", v["reason"])

    def test_divergent_same_status_bodies_suspected(self):
        v = burst_verdict([outcome(0, 200, ok=True, sha="a"),
                           outcome(1, 409, sha="b1"),
                           outcome(2, 409, sha="b2")],
                          expect_success_max=1)
        self.assertEqual(v["verdict"], "suspected")
        self.assertEqual(v["divergent_statuses"], [409])
        self.assertIn("different bodies", v["reason"])

    def test_consistent_conflicts_are_no_issue(self):
        v = burst_verdict([outcome(0, 200, ok=True, sha="ok"),
                           outcome(1, 409, sha="conf"),
                           outcome(2, 409, sha="conf")],
                          expect_success_max=1)
        self.assertEqual(v["verdict"], "no_issue")
        self.assertIn("serializes", v["reason"])

    def test_unexpected_status_outranks_divergence(self):
        v = burst_verdict([outcome(0, 200, ok=True, sha="a"),
                           outcome(1, 500, sha="b"),
                           outcome(2, 409, sha="c1"),
                           outcome(3, 409, sha="c2")],
                          expect_success_max=1)
        self.assertEqual(v["verdict"], "suspected")
        self.assertIn("unexpected_statuses", v)
        self.assertNotIn("divergent_statuses", v)

    def test_custom_success_statuses_respected(self):
        v = burst_verdict([outcome(0, 201, ok=True, sha="a"),
                           outcome(1, 409, sha="b")],
                          expect_success_max=1,
                          success_statuses={201})
        self.assertEqual(v["verdict"], "no_issue")


class FakeRaceResp:
    def __init__(self, status=200, text=""):
        self.status_code = status
        self.text = text


class FakeRaceSession:
    queue: list = []
    instances: list = []
    raise_exc: Exception | None = None

    def __init__(self, guard=None, timeout=None, max_redirects=None, **kw):
        self.headers: dict[str, str] = {}
        self.calls: list[dict] = []
        type(self).instances.append(self)

    def set_default_header(self, name, value):
        self.headers[name] = value

    def request(self, method, url, headers=None, data=None, json=None, **kw):
        if FakeRaceSession.raise_exc is not None:
            raise FakeRaceSession.raise_exc
        self.calls.append({"method": method, "url": url, "data": data,
                           "json": json})
        if FakeRaceSession.queue:
            return FakeRaceSession.queue.pop(0)
        return FakeRaceResp(500, "no scripted response")


class FakeSeedIdentity:
    def default_headers(self):
        return {"Authorization": "Bearer SEED-TOKEN"}

    def cookies(self):
        return {"session": "SEEDCOOKIE123"}

    def cookie_header(self):
        return ""

    def request(self, *a, **kw):
        return FakeRaceResp()

    def get(self, url, **kw):
        return FakeRaceResp()


IDENT = IdentityConfig(name="alice", kind="cookie",
                       cookie_env="T_RACE_COOKIE")


class Base(unittest.TestCase):
    def setUp(self):
        redactor.clear()
        FakeRaceSession.queue = []
        FakeRaceSession.instances = []
        FakeRaceSession.raise_exc = None
        self._patcher = mock.patch("redteam.tools.race.ScopedSession",
                                   FakeRaceSession)
        self._patcher.start()
        self.addCleanup(self._patcher.stop)

    def tearDown(self):
        redactor.clear()

    def tool(self, identities=(), enabled=True) -> RaceBurstTool:
        return RaceBurstTool(
            SessionManager(list(identities), make_guard(domains=ALLOWED)),
            enabled=enabled)

    def logged_in_tool(self, enabled=True) -> RaceBurstTool:
        mgr = SessionManager([IDENT], make_guard(domains=ALLOWED))
        mgr._sessions["alice"] = FakeSeedIdentity()
        return RaceBurstTool(mgr, enabled=enabled)


class TestRaceToolGates(Base):
    def test_disabled_refuses(self):
        with self.assertRaises(ToolError) as cm:
            self.tool(enabled=False).run({"url": URL, "method": "POST"})
        self.assertIn("business_logic", str(cm.exception))
        self.assertEqual(FakeRaceSession.instances, [])

    def test_count_bounds(self):
        for count in (1, 6, 0, -1):
            with self.assertRaises(ToolError):
                self.tool().run({"url": URL, "method": "POST", "count": count})
        with self.assertRaises(ToolError):
            self.tool().run({"url": URL, "method": "POST", "count": "many"})
        self.assertEqual(FakeRaceSession.instances, [])

    def test_write_methods_only(self):
        for method in ("GET", "DELETE", "TRACE"):
            with self.assertRaises(ToolError):
                self.tool().run({"url": URL, "method": method})
        self.assertEqual(FakeRaceSession.instances, [])

    def test_url_scheme_checked(self):
        with self.assertRaises(ToolError):
            self.tool().run({"url": "ftp://shop.test/x", "method": "POST"})

    def test_invariant_bounds_checked(self):
        with self.assertRaises(ToolError):   # above burst size
            self.tool().run({"url": URL, "method": "POST", "count": 2,
                             "expect_success_max": 3})
        with self.assertRaises(ToolError):   # negative
            self.tool().run({"url": URL, "method": "POST",
                             "expect_success_max": -1})

    def test_expect_status_validated(self):
        with self.assertRaises(ToolError):
            self.tool().run({"url": URL, "method": "POST",
                             "expect_status": "two-hundred"})
        with self.assertRaises(ToolError):
            self.tool().run({"url": URL, "method": "POST",
                             "expect_status": 700})

    def test_unlogged_identity_refused(self):
        with self.assertRaises(ToolError) as cm:
            self.tool(identities=(IDENT,)).run(
                {"url": URL, "method": "POST", "identity": "alice"})
        self.assertIn("session_login", str(cm.exception))
        self.assertEqual(FakeRaceSession.instances, [])


class TestRaceToolBurst(Base):
    def test_anonymous_burst_fires_count_workers(self):
        FakeRaceSession.queue = [FakeRaceResp(200, "ok"),
                                 FakeRaceResp(409, "conflict"),
                                 FakeRaceResp(409, "conflict")]
        res = self.tool().run({"url": URL, "method": "POST", "count": 3,
                               "data": {"coupon": "SAVE10"}})
        self.assertEqual(len(FakeRaceSession.instances), 3)
        for inst in FakeRaceSession.instances:
            self.assertEqual(len(inst.calls), 1)
            self.assertEqual(inst.calls[0]["method"], "POST")
            self.assertEqual(inst.calls[0]["data"], {"coupon": "SAVE10"})
        self.assertEqual(sorted(res.data["statuses"]), [200, 409, 409])
        self.assertEqual(res.data["success_count"], 1)
        self.assertEqual(res.data["verdict"], "no_issue")

    def test_every_worker_seeded_with_identity_credentials(self):
        FakeRaceSession.queue = [FakeRaceResp(409, "conflict"),
                                 FakeRaceResp(200, "ok")]
        self.logged_in_tool().run({"url": URL, "method": "POST", "count": 2,
                                   "identity": "alice"})
        self.assertEqual(len(FakeRaceSession.instances), 2)
        for inst in FakeRaceSession.instances:
            self.assertEqual(inst.headers.get("Cookie"), "session=SEEDCOOKIE123")
            self.assertEqual(inst.headers.get("Authorization"),
                             "Bearer SEED-TOKEN")

    def test_double_spend_confirmed_with_evidence(self):
        FakeRaceSession.queue = [FakeRaceResp(200, '{"applied": true}'),
                                 FakeRaceResp(200, '{"applied": true}'),
                                 FakeRaceResp(409, "already redeemed")]
        res = self.tool().run({"url": URL, "method": "POST", "count": 3})
        self.assertEqual(res.data["verdict"], "confirmed")
        self.assertEqual(res.data["cwe"], "CWE-362")
        self.assertIn("record_finding with status 'confirmed'",
                      res.data["recommendation"])
        self.assertIn("status", res.data["evidence"])
        self.assertIn("req 0:", res.data["evidence"])
        self.assertIn("3 concurrent POST", res.data["evidence"])

    def test_marker_and_custom_expect_status_paths(self):
        FakeRaceSession.queue = [FakeRaceResp(200, "REDEEMED ok"),
                                 FakeRaceResp(409, "conflict")]
        res = self.tool().run({"url": URL, "method": "POST", "count": 2,
                               "success_marker": "REDEEMED"})
        self.assertEqual(res.data["success_count"], 1)
        self.assertEqual(res.data["verdict"], "no_issue")

        FakeRaceSession.queue = [FakeRaceResp(201, "created"),
                                 FakeRaceResp(409, "conflict")]
        res = self.tool().run({"url": URL, "method": "POST", "count": 2,
                               "expect_status": 201})
        self.assertEqual(res.data["success_count"], 1)
        self.assertEqual(res.data["verdict"], "no_issue")

    def test_all_transport_errors_inconclusive(self):
        FakeRaceSession.raise_exc = requests.ConnectionError("refused")
        res = self.tool().run({"url": URL, "method": "POST", "count": 2})
        self.assertEqual(res.data["verdict"], "inconclusive")
        self.assertIn("do NOT record", res.data["recommendation"])

    def test_scope_violation_propagates_from_worker(self):
        # must NOT be swallowed as a transport error — stage abort invariant
        FakeRaceSession.raise_exc = ScopeViolation("host not in scope")
        with self.assertRaises(ScopeViolation):
            self.tool().run({"url": URL, "method": "POST", "count": 2})

    def test_registered_secrets_redacted_from_evidence(self):
        redactor.register("MY-SECRET-VALUE")
        FakeRaceSession.queue = [FakeRaceResp(200, "My-SECRET-VALUE".upper()),
                                 FakeRaceResp(409, "conflict")]
        res = self.tool().run({"url": URL, "method": "POST", "count": 2})
        self.assertNotIn("MY-SECRET-VALUE", res.data["evidence"])
        self.assertIn("[REDACTED]", res.data["evidence"])


class TestOrchestratorRegistration(unittest.TestCase):
    def test_race_burst_registered_and_gated(self):
        from redteam.orchestrator import ACTIVE_TOOLS, Orchestrator
        root = Path(__file__).resolve().parent.parent
        cfg = load_config(root / "config.example.yaml")
        tmp = Path(tempfile.mkdtemp())
        cfg = replace(cfg, safety=replace(
            cfg.safety, artifacts_dir=str(tmp / "art"),
            cassette_dir=str(tmp / "cass"), runner="local"))
        orch = Orchestrator(cfg)
        tool = orch.registry.get("race_burst")
        self.assertIsNotNone(tool)
        self.assertFalse(tool.inner.enabled)   # config.example: business_logic false
        self.assertIn("race_burst", ACTIVE_TOOLS)
        with self.assertRaises(ToolError):
            tool.run({"url": URL, "method": "POST"})


if __name__ == "__main__":
    unittest.main()
