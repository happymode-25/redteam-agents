"""Phase 2.4 — business-logic workflow state machine (catalog section 11).

Pure tests for parse_steps/resolve_next, artifact save/load (redacted),
tool-level execution against scripted sessions (zero network), and the
orchestrator gate: disabled-by-default refusal, ACTIVE_TOOLS membership,
and the operator prompts that must show the real method + URL.
"""

from __future__ import annotations

import json
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest import mock

from redteam.auth import SessionManager
from redteam.config import IdentityConfig, SafetyConfig, load_config
from redteam.redact import redactor
from redteam.scope import ScopeViolation
from redteam.tools.base import ToolError
from redteam.tools.workflow import (_ANON_SESSIONS, MAX_PLAN_STEPS, Workflow,
                                    WorkflowPlanTool, WorkflowStatusTool,
                                    WorkflowStepTool, parse_steps, resolve_next)

from test_phase1 import make_guard

ALLOWED = ("shop.test",)


def flow_steps() -> list[dict]:
    return [
        {"name": "add-to-cart", "method": "POST",
         "url": "https://shop.test/api/cart", "data": {"id": "1"}},
        {"name": "checkout", "method": "POST",
         "url": "https://shop.test/api/checkout",
         "json": {"coupon": "SAVE10"}, "expect_status": [200, 201]},
    ]


class FakeFlowResp:
    def __init__(self, status=200, text="{}"):
        self.status_code = status
        self.text = text


class FakeFlowSession:
    """Identity session stub: records requests, serves scripted responses."""

    def __init__(self, responses=None):
        self.responses = list(responses or [])
        self.calls: list[dict] = []

    def request(self, method, url, headers=None, data=None, json=None, **kw):
        self.calls.append({"method": method, "url": url, "data": data,
                           "json": json, "headers": headers})
        if self.responses:
            return self.responses.pop(0)
        return FakeFlowResp()

    def get(self, url, **kw):
        return self.request("GET", url, **kw)


class FakeAnonSession:
    """Stands in for the anonymous ScopedSession (patched at module level)."""

    instances: list = []

    def __init__(self, guard=None, **kwargs):
        self.responses: list = []
        self.calls: list[dict] = []
        type(self).instances.append(self)

    def set_default_header(self, name, value):
        pass

    def request(self, method, url, headers=None, data=None, json=None, **kw):
        self.calls.append({"method": method, "url": url})
        if self.responses:
            return self.responses.pop(0)
        return FakeFlowResp()

    def get(self, url, **kw):
        return self.request("GET", url, **kw)


IDENT = IdentityConfig(name="alice", kind="cookie",
                       cookie_env="T_WF_COOKIE")


class Base(unittest.TestCase):
    def setUp(self):
        redactor.clear()
        self.tmp = Path(tempfile.mkdtemp())
        _ANON_SESSIONS.clear()
        FakeAnonSession.instances = []
        self._patcher = mock.patch("redteam.tools.workflow.ScopedSession",
                                   FakeAnonSession)
        self._patcher.start()
        self.addCleanup(self._patcher.stop)

    def tearDown(self):
        redactor.clear()
        _ANON_SESSIONS.clear()

    def plan_tool(self, identities=(IDENT,), enabled=True) -> WorkflowPlanTool:
        return WorkflowPlanTool(
            SessionManager(list(identities), make_guard(domains=ALLOWED)),
            self.tmp, enabled=enabled)

    def step_tool(self, sessions=None, enabled=True) -> WorkflowStepTool:
        sessions = sessions or SessionManager([IDENT],
                                              make_guard(domains=ALLOWED))
        return WorkflowStepTool(sessions, self.tmp, enabled=enabled)

    def make_plan(self, tool=None, steps=None, **extra) -> str:
        tool = tool or self.plan_tool()
        args = {"steps": steps if steps is not None else flow_steps()}
        args.update(extra)
        return tool.run(args).data["plan_id"]


class TestParseSteps(unittest.TestCase):
    def test_empty_rejected(self):
        with self.assertRaises(ToolError):
            parse_steps([])
        with self.assertRaises(ToolError):
            parse_steps(None)
        with self.assertRaises(ToolError):
            parse_steps("add cart")

    def test_too_many_steps_rejected(self):
        steps = [{"method": "GET", "url": "https://shop.test/x"}] * (
            MAX_PLAN_STEPS + 1)
        with self.assertRaises(ToolError) as cm:
            parse_steps(steps)
        self.assertIn(str(MAX_PLAN_STEPS), str(cm.exception))

    def test_duplicate_names_rejected(self):
        steps = [{"name": "same", "method": "GET", "url": "https://shop.test/a"},
                 {"name": "same", "method": "GET", "url": "https://shop.test/b"}]
        with self.assertRaises(ToolError) as cm:
            parse_steps(steps)
        self.assertIn("duplicate", str(cm.exception))

    def test_bad_method_rejected(self):
        with self.assertRaises(ToolError):
            parse_steps([{"method": "TRACE", "url": "https://shop.test/x"}])

    def test_non_http_url_rejected(self):
        with self.assertRaises(ToolError):
            parse_steps([{"method": "GET", "url": "ftp://shop.test/x"}])

    def test_bad_data_shapes_rejected(self):
        with self.assertRaises(ToolError):   # data not an object
            parse_steps([{"method": "POST", "url": "https://shop.test/x",
                          "data": "id=1"}])
        with self.assertRaises(ToolError):   # nested value not scalar
            parse_steps([{"method": "POST", "url": "https://shop.test/x",
                          "data": {"nested": {"a": 1}}}])
        with self.assertRaises(ToolError):   # header values must be strings
            parse_steps([{"method": "GET", "url": "https://shop.test/x",
                          "headers": {"X-Num": 5}}])

    def test_expect_status_range_checked(self):
        with self.assertRaises(ToolError):
            parse_steps([{"method": "GET", "url": "https://shop.test/x",
                          "expect_status": 99}])
        with self.assertRaises(ToolError):
            parse_steps([{"method": "GET", "url": "https://shop.test/x",
                          "expect_status": "two-hundred"}])

    def test_defaults_applied(self):
        steps = parse_steps([{"url": "https://shop.test/x"}])
        self.assertEqual(steps[0].method, "GET")
        self.assertEqual(steps[0].name, "step1")


class TestResolveNext(unittest.TestCase):
    def wf(self, transitions=0) -> Workflow:
        steps = parse_steps(flow_steps())
        return Workflow(id="abcd1234", label="t", identity="",
                        created_at="now", steps=steps,
                        transitions=[{"name": "add-to-cart"}] * transitions)

    def test_default_resolves_next(self):
        idx, step = resolve_next(self.wf(0), None)
        self.assertEqual((idx, step.name), (0, "add-to-cart"))
        idx, step = resolve_next(self.wf(1), "next")
        self.assertEqual((idx, step.name), (1, "checkout"))

    def test_name_and_index_of_next_ok(self):
        self.assertEqual(resolve_next(self.wf(0), "add-to-cart")[0], 0)
        self.assertEqual(resolve_next(self.wf(1), "2")[0], 1)

    def test_out_of_order_refused_with_state(self):
        with self.assertRaises(ToolError) as cm:
            resolve_next(self.wf(0), "checkout")
        msg = str(cm.exception)
        self.assertIn("steps run in order", msg)
        self.assertIn("add-to-cart", msg)     # pending list
        self.assertIn("none", msg)            # executed list

    def test_rerun_of_executed_step_refused(self):
        with self.assertRaises(ToolError) as cm:
            resolve_next(self.wf(1), "add-to-cart")
        self.assertIn("executed: ['add-to-cart']", str(cm.exception))

    def test_complete_workflow_refused(self):
        with self.assertRaises(ToolError) as cm:
            resolve_next(self.wf(2), None)
        self.assertIn("complete", str(cm.exception))

    def test_unknown_step_refused(self):
        with self.assertRaises(ToolError):
            resolve_next(self.wf(0), "nonexistent")
        with self.assertRaises(ToolError):
            resolve_next(self.wf(0), "99")


class TestWorkflowArtifact(Base):
    def test_save_load_round_trip(self):
        wf = Workflow(id="abcd1234", label="checkout flow", identity="alice",
                      created_at="now", steps=parse_steps(flow_steps()))
        wf.save(self.tmp)
        loaded = Workflow.load(self.tmp, "abcd1234")
        self.assertEqual(loaded.label, "checkout flow")
        self.assertEqual([s.name for s in loaded.steps],
                         ["add-to-cart", "checkout"])
        self.assertEqual(loaded.steps[1].expect_status, [200, 201])
        self.assertEqual(loaded.steps[0].data, {"id": "1"})

    def test_artifact_passes_through_redaction(self):
        redactor.register("MY-SECRET-VALUE")
        steps = [{"name": "auth", "method": "POST",
                  "url": "https://shop.test/login",
                  "headers": {"X-Token": "MY-SECRET-VALUE"}}]
        self.make_plan(steps=steps)
        path = next(self.tmp.glob("workflow-*.json"))
        text = path.read_text(encoding="utf-8")
        self.assertNotIn("MY-SECRET-VALUE", text)
        self.assertIn("[REDACTED]", text)

    def test_bad_plan_ids_refused(self):
        for bad in ("", "nope", "../../etc/passwd", "ABCD1234"):
            with self.assertRaises(ToolError):
                Workflow.load(self.tmp, bad)

    def test_unknown_plan_refused(self):
        with self.assertRaises(ToolError) as cm:
            Workflow.load(self.tmp, "deadbeef")
        self.assertIn("workflow_plan", str(cm.exception))


class TestPlanTool(Base):
    def test_disabled_refuses_before_anything(self):
        tool = self.plan_tool(enabled=False)
        with self.assertRaises(ToolError) as cm:
            tool.run({"steps": flow_steps()})
        self.assertIn("business_logic", str(cm.exception))
        self.assertEqual(list(self.tmp.glob("workflow-*.json")), [])

    def test_plan_returns_id_and_artifact(self):
        res = self.plan_tool().run({
            "label": "checkout with coupon", "steps": flow_steps(),
            "identity": "alice"})
        self.assertEqual(len(res.data["plan_id"]), 8)
        self.assertEqual(res.data["steps"], ["add-to-cart", "checkout"])
        self.assertEqual(res.data["next_step"], "add-to-cart")
        self.assertTrue(Path(res.data["artifact"]).exists())
        self.assertIn("Nothing was sent", res.summary)

    def test_unknown_identity_refused(self):
        with self.assertRaises(ToolError):
            self.plan_tool().run({"steps": flow_steps(), "identity": "nobody"})
        self.assertEqual(list(self.tmp.glob("workflow-*.json")), [])

    def test_scope_violation_propagates_and_no_plan_written(self):
        steps = [{"name": "evil", "method": "GET",
                  "url": "https://evil.example/x"}]
        with self.assertRaises(ScopeViolation):
            self.plan_tool().run({"steps": steps})
        self.assertEqual(list(self.tmp.glob("workflow-*.json")), [])


class TestStepTool(Base):
    def test_requires_login_for_identity_flow(self):
        pid = self.make_plan(identity="alice")   # configured, never logged in
        tool = self.step_tool()
        with self.assertRaises(ToolError) as cm:
            tool.run({"plan_id": pid})
        self.assertIn("session_login", str(cm.exception))

    def test_identity_step_runs_in_order_with_evidence(self):
        pid = self.make_plan(identity="alice")
        fake = FakeFlowSession(responses=[
            FakeFlowResp(201, '{"cart": {"total": 10}}'),
            FakeFlowResp(200, '{"order": 42}'),
        ])
        mgr = SessionManager([IDENT], make_guard(domains=ALLOWED))
        mgr._sessions["alice"] = fake
        tool = self.step_tool(sessions=mgr)

        first = tool.run({"plan_id": pid})
        self.assertEqual(first.data["status"], 201)
        self.assertTrue(first.data["expect_met"])
        self.assertEqual(first.data["result"], "expected")
        self.assertEqual(first.data["next_step"], "checkout")
        self.assertIn("status", first.data["evidence"])
        self.assertIn("response:", first.data["evidence"])
        self.assertEqual(fake.calls[0]["method"], "POST")
        self.assertEqual(fake.calls[0]["data"], {"id": "1"})

        second = tool.run({"plan_id": pid, "step": "checkout"})
        self.assertEqual(second.data["index"], 2)
        self.assertTrue(second.data["complete"])
        self.assertEqual(second.data["next_step"], None)
        self.assertEqual(fake.calls[1]["json"], {"coupon": "SAVE10"})
        # the recorded state machine persisted both transitions
        wf = Workflow.load(self.tmp, pid)
        self.assertEqual([t["name"] for t in wf.transitions],
                         ["add-to-cart", "checkout"])
        self.assertEqual(wf.transitions[1]["status"], 200)

    def test_out_of_order_sends_nothing(self):
        pid = self.make_plan(identity="alice")
        fake = FakeFlowSession()
        mgr = SessionManager([IDENT], make_guard(domains=ALLOWED))
        mgr._sessions["alice"] = fake
        tool = self.step_tool(sessions=mgr)
        with self.assertRaises(ToolError) as cm:
            tool.run({"plan_id": pid, "step": "checkout"})
        self.assertIn("steps run in order", str(cm.exception))
        self.assertEqual(fake.calls, [])

    def test_unexpected_status_flagged(self):
        pid = self.make_plan(identity="alice")
        fake = FakeFlowSession(responses=[
            FakeFlowResp(500, "boom"),
            FakeFlowResp(403, "no"),
        ])
        mgr = SessionManager([IDENT], make_guard(domains=ALLOWED))
        mgr._sessions["alice"] = fake
        tool = self.step_tool(sessions=mgr)

        res = tool.run({"plan_id": pid})
        self.assertFalse(res.data["expect_met"])
        self.assertEqual(res.data["result"], "unexpected_status")
        self.assertIn("record_finding", res.data["recommendation"])

        res2 = tool.run({"plan_id": pid})
        self.assertFalse(res2.data["expect_met"])   # 403 vs [200, 201]

    def test_anonymous_flow_reuses_one_session(self):
        pid = self.make_plan()                      # no identity
        tool = self.step_tool()
        tool.run({"plan_id": pid})
        tool.run({"plan_id": pid})
        self.assertEqual(len(FakeAnonSession.instances), 1)  # cookie continuity
        self.assertEqual(len(FakeAnonSession.instances[0].calls), 2)

    def test_disabled_refuses_before_loading(self):
        tool = self.step_tool(enabled=False)
        with self.assertRaises(ToolError) as cm:
            tool.run({"plan_id": "abcd1234"})
        self.assertIn("business_logic", str(cm.exception))

    def test_response_secrets_are_redacted_in_evidence_and_artifact(self):
        redactor.register("LEAKED-SESSION-999")
        pid = self.make_plan(identity="alice")
        fake = FakeFlowSession(responses=[
            FakeFlowResp(200, '{"token": "LEAKED-SESSION-999"}')])
        mgr = SessionManager([IDENT], make_guard(domains=ALLOWED))
        mgr._sessions["alice"] = fake
        res = self.step_tool(sessions=mgr).run({"plan_id": pid})
        self.assertNotIn("LEAKED-SESSION-999", res.data["evidence"])
        self.assertIn("[REDACTED]", res.data["evidence"])
        text = (self.tmp / f"workflow-{pid}.json").read_text(encoding="utf-8")
        self.assertNotIn("LEAKED-SESSION-999", text)

    def test_plan_id_format_checked(self):
        tool = self.step_tool()
        with self.assertRaises(ToolError):
            tool.run({"plan_id": "not-a-plan"})


class TestStatusTool(Base):
    def test_reports_state_machine(self):
        pid = self.make_plan(identity="alice")
        fake = FakeFlowSession()
        mgr = SessionManager([IDENT], make_guard(domains=ALLOWED))
        mgr._sessions["alice"] = fake
        self.step_tool(sessions=mgr).run({"plan_id": pid})

        res = WorkflowStatusTool(self.tmp).run({"plan_id": pid})
        self.assertEqual(res.data["executed"], ["add-to-cart"])
        self.assertEqual(res.data["pending"], ["checkout"])
        self.assertEqual(res.data["next_step"], "checkout")
        self.assertEqual(res.data["transitions"][0]["status"], 200)
        self.assertEqual(res.data["total_steps"], 2)

    def test_unknown_plan_refused(self):
        with self.assertRaises(ToolError):
            WorkflowStatusTool(self.tmp).run({"plan_id": "deadbeef"})


class TestOrchestratorGate(unittest.TestCase):
    def setUp(self):
        root = Path(__file__).resolve().parent.parent
        cfg = load_config(root / "config.example.yaml")
        tmp = Path(tempfile.mkdtemp())
        self.cfg = replace(cfg, safety=replace(
            cfg.safety, artifacts_dir=str(tmp / "art"),
            cassette_dir=str(tmp / "cass"), runner="local"))
        from redteam.orchestrator import Orchestrator
        self.orch = Orchestrator(self.cfg)

    def test_tools_registered_and_disabled_by_default(self):
        reg = self.orch.registry
        for name in ("workflow_plan", "workflow_step", "workflow_status",
                     "race_burst"):
            self.assertIsNotNone(reg.get(name), name)
        # config.example ships business_logic: false -> execution refused
        self.assertFalse(self.cfg.safety.business_logic)
        with self.assertRaises(ToolError) as cm:
            reg.get("workflow_plan").run({"steps": flow_steps()})
        self.assertIn("business_logic", str(cm.exception))

    def test_config_default_is_off(self):
        self.assertFalse(SafetyConfig().business_logic)

    def test_only_step_and_burst_are_operator_gated(self):
        from redteam.orchestrator import ACTIVE_TOOLS
        self.assertIn("workflow_step", ACTIVE_TOOLS)
        self.assertIn("race_burst", ACTIVE_TOOLS)
        self.assertNotIn("workflow_plan", ACTIVE_TOOLS)
        self.assertNotIn("workflow_status", ACTIVE_TOOLS)

    def test_workflow_prompt_shows_real_method_and_url(self):
        plan = {"id": "abcd1234", "label": "flow", "identity": "",
                "created_at": "t",
                "steps": [{"name": "pay", "method": "POST",
                           "url": "https://shop.test/api/pay"}],
                "transitions": []}
        (self.orch.artifacts / "workflow-abcd1234.json").write_text(
            json.dumps(plan), encoding="utf-8")
        prompt = self.orch._active_prompt("workflow_step",
                                          {"plan_id": "abcd1234"})
        self.assertIn("POST https://shop.test/api/pay", prompt)
        self.assertIn("step 1/1", prompt)
        self.assertIn("pay", prompt)

    def test_workflow_prompt_falls_back_for_unknown_plan(self):
        prompt = self.orch._active_prompt("workflow_step",
                                          {"plan_id": "deadbeef"})
        self.assertIn("workflow_step", prompt)
        self.assertIn("deadbeef", prompt)

    def test_race_prompt_shows_burst_size(self):
        prompt = self.orch._active_prompt(
            "race_burst", {"method": "POST", "url": "https://shop.test/x",
                           "count": 3})
        self.assertIn("POST https://shop.test/x", prompt)
        self.assertIn("3 concurrent", prompt)

    def test_default_prompt_unchanged_for_http_request(self):
        prompt = self.orch._active_prompt(
            "http_request", {"method": "GET", "url": "https://shop.test/"})
        self.assertEqual(prompt, "GET https://shop.test/")

    def test_operator_rejection_raises_scope_violation(self):
        from redteam.scope import ScopeViolation
        with mock.patch("builtins.input", return_value="n"):
            with self.assertRaises(ScopeViolation):
                self.orch._pre_tool_hook(
                    "race_burst",
                    {"method": "POST", "url": "https://shop.test/x"})

    def test_operator_acceptance_records_used_tool(self):
        with mock.patch("builtins.input", return_value="y"):
            self.orch._pre_tool_hook(
                "http_request", {"method": "GET", "url": "https://shop.test/"})
        self.assertIn("http_request", self.orch.used_tools)


if __name__ == "__main__":
    unittest.main()
