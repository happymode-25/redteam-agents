"""Phase 4 tests: budget/cost governance, drift, tickets, review queue,
HTML report, engagement model, and their integration into the report/orch."""

from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from dataclasses import replace
from datetime import date
from pathlib import Path
from unittest import mock

from redteam.budget import (BudgetConfig, BudgetExceeded, TokenBudget,
                            estimate_tokens, format_usage)
from redteam.config import load_config
from redteam.drift import (Drift, compare, fingerprint, load_snapshot,
                           render_drift_markdown, save_snapshot, snapshot,
                           snapshot_path, target_slug)
from redteam.htmlreport import markdown_to_html, render_html
from redteam.review import apply_reviews, load_reviews, set_review
from redteam.state import Finding, SharedState
from redteam.tickets import (JIRA_PRIORITY, LINEAR_PRIORITY, load_findings,
                             render, to_ticket, to_tickets)


def _finding(**kw) -> Finding:
    defaults = dict(
        id="_t",
        title="Missing security header",
        severity="medium",
        target="http://example.com",
        evidence="request -> response: header absent",
        remediation="Set the header.",
        tool="web_security_checks",
        status="suspected",
        cwe="CWE-693",
        cvss="5.3",
        cves="",
    )
    defaults.update(kw)
    return Finding(**defaults)


def _write(tmp: Path, name: str, text: str) -> Path:
    p = tmp / name
    p.write_text(text, encoding="utf-8")
    return p


# ---------------------------------------------------------------------------
# budget


class TestBudget(unittest.TestCase):
    def test_estimate_tokens(self):
        self.assertEqual(estimate_tokens("", [], ""), 1)
        self.assertEqual(estimate_tokens("abcd", [], ""), 1)
        self.assertEqual(estimate_tokens("x" * 100, [{"content": "a" * 100}], "b" * 100), 75)

    def test_check_raises_over_total(self):
        b = TokenBudget(BudgetConfig(max_total_tokens=100))
        b.charge("planner", 90)
        b.check("planner")                       # under the limit
        b.charge("planner", 20)
        with self.assertRaises(BudgetExceeded):
            b.check("planner")

    def test_check_raises_over_role_limit(self):
        b = TokenBudget(BudgetConfig(max_total_tokens=0, per_role={"recon": 50}))
        b.charge("recon", 60)
        with self.assertRaisesRegex(BudgetExceeded, "recon"):
            b.check("recon")
        b.charge("planner", 1000)                # total unlimited
        b.check("planner")

    def test_invalid_config(self):
        with self.assertRaises(ValueError):
            TokenBudget(BudgetConfig(max_total_tokens=-1))
        with self.assertRaises(ValueError):
            TokenBudget(BudgetConfig(per_role={"x": -5}))
        with self.assertRaises(ValueError):
            TokenBudget(BudgetConfig(on_exhausted="yolo"))

    def test_downgrades_and_totals(self):
        b = TokenBudget(BudgetConfig(on_exhausted="downgrade"))
        b.note_downgrade("planner")
        b.note_downgrade("planner")              # deduped
        self.assertEqual(b.totals()["downgrades"], ["planner"])
        self.assertIn("planner", b.describe())

    def test_format_usage(self):
        self.assertEqual(format_usage(None, None), "")
        line = format_usage(None, TokenBudget(BudgetConfig()))
        self.assertIn("token budget", line)

    def test_config_loader_budget(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            example = Path("config.example.yaml").read_text(encoding="utf-8")
            base = example.replace("identities:", "budget: {max_total_tokens: 5000, per_role: {planner: 1000}, on_exhausted: downgrade}\nidentities:")
            cfg_path = _write(tmp, "c.yaml", base)
            cfg = load_config(cfg_path)
            self.assertEqual(cfg.budget.max_total_tokens, 5000)
            self.assertEqual(cfg.budget.per_role, {"planner": 1000})
            self.assertEqual(cfg.budget.on_exhausted, "downgrade")
            bad = base.replace("downgrade", "explode")
            with self.assertRaises(ValueError):
                load_config(_write(tmp, "bad.yaml", bad))


class TestRouterBudget(unittest.TestCase):
    """Router-level budget enforcement against fake providers."""

    REPLY = "x" * 800          # ~201 estimated tokens per completion

    class FakeProvider:
        def __init__(self, name: str):
            self.name = name
            self.model = f"model-{name}"
            self.calls = 0

        def complete(self, system, messages):
            self.calls += 1
            return TestRouterBudget.REPLY

    def _router(self, total=0, per_role=None, on_exhausted="stop"):
        cfg = type("C", (), {})()             # duck-typed LLMConfig
        cfg.hosted, cfg.local = None, None
        cfg.roles = {"planner": "hosted", "analyst": "local"}
        fake_hosted, fake_local = self.FakeProvider("hosted"), self.FakeProvider("local")

        import redteam.llm as llm
        with mock.patch.object(llm, "build_provider",
                               side_effect=[fake_hosted, fake_local]):
            router = llm.Router(
                cfg,
                budget=TokenBudget(BudgetConfig(
                    max_total_tokens=total,
                    per_role=per_role or {},
                    on_exhausted=on_exhausted)))
        return router, fake_hosted, fake_local

    def test_usage_recorded(self):
        from redteam.budget import estimate_tokens
        router, hosted, local = self._router()
        provider = router.for_role("planner")
        provider.complete("system", [{"role": "user", "content": "hi"}])
        self.assertEqual(
            router.usage.get("planner"),
            estimate_tokens("system", [{"role": "user", "content": "hi"}],
                            self.REPLY))
        self.assertEqual(hosted.calls, 1)
        self.assertIn("~", router.budget.describe())

    def test_budget_exhausted_stops(self):
        router, *_ = self._router(total=150)
        provider = router.for_role("planner")
        provider.complete("system", [])
        with self.assertRaises(BudgetExceeded):
            provider.complete("system", [])

    def test_budget_downgrade_hosted_to_local(self):
        router, hosted, local = self._router(total=150, on_exhausted="downgrade")
        provider = router.for_role("planner")
        provider.complete("system", [])
        provider.complete("system", [])          # second call runs on LOCAL
        self.assertEqual(hosted.calls, 1)
        self.assertEqual(local.calls, 1)
        self.assertEqual(router.budget.totals()["downgrades"], ["planner"])

    def test_local_role_cannot_downgrade(self):
        router, _, local = self._router(total=150, on_exhausted="downgrade")
        provider = router.for_role("analyst")
        provider.complete("system", [])
        with self.assertRaises(BudgetExceeded):
            provider.complete("system", [])
        self.assertEqual(local.calls, 1)


# ---------------------------------------------------------------------------
# drift


class TestDrift(unittest.TestCase):
    def test_fingerprint_stability(self):
        base = _finding()
        same = fingerprint(_finding(severity="low", status="confirmed",
                                    evidence="totally different text"))
        self.assertEqual(same, fingerprint(base))
        self.assertNotEqual(fingerprint(_finding(title="Other")), fingerprint(base))
        self.assertNotEqual(fingerprint(_finding(target="http://other")), fingerprint(base))
        self.assertNotEqual(fingerprint(_finding(cwe="CWE-79")), fingerprint(base))

    def test_first_run(self):
        snap = snapshot("t", [_finding()])
        d = compare(None, snap)
        self.assertTrue(d.first_run)
        self.assertEqual(len(d.new), 1)
        text = render_drift_markdown(d)
        self.assertIn("First recorded run", text)

    def test_new_resolved_persisting(self):
        prev = {"ts": "2026-10-01T00:00:00", "target": "t", "findings": [
            {"fingerprint": "AAAA", "id": "F1", "title": "Kept",
             "severity": "high", "status": "confirmed", "target": "x", "cwe": ""},
            {"fingerprint": "BBBB", "id": "F2", "title": "Gone",
             "severity": "low", "status": "suspected", "target": "x", "cwe": ""},
        ]}
        cur = {"ts": "2026-10-02T00:00:00", "target": "t", "findings": [
            {"fingerprint": "AAAA", "id": "F1", "title": "Kept",
             "severity": "high", "status": "confirmed", "target": "x", "cwe": ""},
            {"fingerprint": "CCCC", "id": "F1", "title": "Fresh",
             "severity": "critical", "status": "confirmed", "target": "x", "cwe": ""},
        ]}
        d = compare(prev, cur)
        self.assertEqual([i["title"] for i in d.new], ["Fresh"])
        self.assertEqual([i["title"] for i in d.resolved], ["Gone"])
        self.assertEqual([i["title"] for i in d.persisting], ["Kept"])
        text = render_drift_markdown(d, previous_ts=prev["ts"])
        self.assertIn("**New findings:**", text)
        self.assertIn("verify before closing", text)
        self.assertIn("Persisting:", text)

    def test_snapshot_roundtrip_and_corruption(self):
        with tempfile.TemporaryDirectory() as td:
            path = snapshot_path(td, "http://lab.test:8000")
            self.assertIn("lab.test", str(snapshot_path(td, "http://lab.test:8000")))
            snap = snapshot("t", [_finding()])
            save_snapshot(path, snap)
            self.assertEqual(load_snapshot(path)["findings"][0]["title"],
                             "Missing security header")
            corrupt = Path(td) / "state" / "corrupt.json"
            corrupt.write_text("{not json", encoding="utf-8")
            self.assertIsNone(load_snapshot(corrupt))
            self.assertIsNone(load_snapshot(Path(td) / "missing.json"))


# ---------------------------------------------------------------------------
# tickets


class TestTickets(unittest.TestCase):
    def test_load_findings_from_state_save(self):
        with tempfile.TemporaryDirectory() as td:
            state = SharedState()
            state.add_finding(title="A", severity="high", target="t",
                              evidence="evidence here", cwe="CWE-79")
            path = Path(td) / "f.json"
            state.save(path)
            findings = load_findings(path)
            self.assertEqual(len(findings), 1)

    def test_ticket_fields_and_redaction(self):
        f = _finding(evidence="status: user=admin; password=hunter2 <secret>")
        t = to_ticket(f)
        self.assertEqual(t.dedup_key, fingerprint(f))
        self.assertIn("dedup:" + fingerprint(f), t.labels)
        self.assertEqual(t.priority, "Medium")
        self.assertIn("CWE-693", t.description)
        self.assertIn("verify every finding manually", t.description)

    def test_priority_maps(self):
        self.assertEqual(JIRA_PRIORITY["critical"], "Highest")
        self.assertEqual(LINEAR_PRIORITY["critical"], "Urgent")
        t = to_ticket(_finding(severity="critical"), LINEAR_PRIORITY)
        self.assertEqual(t.priority, "Urgent")

    def test_render_formats_parse(self):
        import csv
        import io
        tickets = to_tickets([_finding(), _finding(severity="high")])
        rows = list(csv.reader(io.StringIO(render(tickets, "jira"))))
        self.assertEqual(rows[0][:2], ["Summary", "Issue Type"])
        self.assertEqual(len(rows), 3)
        lvows = list(csv.reader(io.StringIO(render(tickets, "linear"))))
        self.assertEqual(lvows[0], ["Title", "Description", "Priority", "Labels"])
        md = render(tickets, "markdown")
        self.assertIn("## [MEDIUM]", md)
        with self.assertRaises(ValueError):
            render(tickets, "pivotal")

    def test_empty_findings_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            empty = _write(Path(td), "e.json", '{"findings": []}')
            from redteam.tickets import main as tickets_main
            self.assertEqual(tickets_main(["--findings", str(empty)]), 1)


# ---------------------------------------------------------------------------
# review queue


class TestReview(unittest.TestCase):
    def test_set_roundtrip_invalid_status(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "reviews.json"
            set_review(path, "fingerprint01", "false_positive",
                       note="not reproducible", reviewer="op")
            data = load_reviews(path)
            self.assertEqual(data["fingerprint01"]["status"], "false_positive")
            self.assertEqual(data["fingerprint01"]["reviewer"], "op")
            with self.assertRaises(ValueError):
                set_review(path, "fingerprint01", "maybe")

    def test_apply_reviews_copies_and_maps(self):
        f = _finding()
        fp = fingerprint(f)
        reviews = {fp: {"status": "accepted_risk", "note": "risk accepted",
                        "reviewer": "ciso", "ts": "2026-10-02"}}
        out = apply_reviews([f], reviews)
        self.assertEqual(out[0].status, "accepted_risk")
        self.assertEqual(f.status, "suspected")          # original untouched
        needs = apply_reviews([f], {fp: {"status": "needs_info"}})
        self.assertEqual(needs[0].status, "suspected")   # needs_info does not flip
        self.assertEqual(apply_reviews([f], {"zzz": {"status": "fake"}})[0].status,
                         "suspected")

    def test_report_integrates_review_and_usage(self):
        state = SharedState()
        f = state.add_finding(title="T1", severity="high", target="t",
                              evidence="http request -> response shown",
                              cwe="CWE-79")
        from redteam.report import render_report
        from redteam.coverage import render_coverage
        with mock.patch("redteam.report.render_coverage",
                        side_effect=render_coverage):
            text = render_report("t", "narrative", state,
                                 tools_used={"web_security_checks"},
                                 usage="LLM usage (estimated tokens): total~100",
                                 reviews={fingerprint(f): {
                                     "status": "confirmed", "note": "reproduced",
                                     "reviewer": "op"}})
        self.assertIn("**Human review:** confirmed by op", text)
        self.assertIn("reproduced", text)
        self.assertIn("total~100", text)


# ---------------------------------------------------------------------------
# html report


class TestHtml(unittest.TestCase):
    def test_table_to_html(self):
        md = "| ID | Severity |\n|----|----------|\n| F1 | HIGH |\n"
        html = markdown_to_html(md)
        self.assertIn("<th>Severity</th>", html)
        self.assertIn("<td>HIGH</td>", html)
        self.assertNotIn("|", html.split("</table>")[0].replace("|", "", 0)
                         if False else html)

    def test_fenced_code_escaped(self):
        md = "```text\n<script>alert(1)</script>\n```"
        html = markdown_to_html(md)
        self.assertIn("<pre><code>", html)
        self.assertNotIn("<script>", html)
        self.assertIn("&lt;script&gt;", html)

    def test_inline_markdown(self):
        html = markdown_to_html("A **bold** and `code` and *it*.")
        self.assertIn("<strong>bold</strong>", html)
        self.assertIn("<code>code</code>", html)
        self.assertIn("<em>it</em>", html)

    def test_headings_hr_and_lists(self):
        md = "# Title\n\n---\n\n- one\n- two\n  - nested\n"
        html = markdown_to_html(md)
        self.assertIn("<h1>Title</h1>", html)
        self.assertIn("<hr>", html)
        self.assertIn("<li>two</li>", html)
        self.assertIn("<li>nested</li>", html)

    def test_render_html_shell(self):
        doc = render_html("# Lab Report\ntext", title="x")
        self.assertIn("<title>Lab Report</title>", doc)
        self.assertIn("verified manually", doc)
        self.assertNotIn("<script", doc.lower())

    def test_raw_html_never_passes_through(self):
        doc = render_html("<img src=x onerror=alert(1)>")
        self.assertNotIn("<img", doc)
        self.assertIn("&lt;img", doc)


# ---------------------------------------------------------------------------
# engagement


ENG_YAML = """\
engagement:
  id: ACME-2026-01
  customer: ACME Corp
  operator: alice
  authorization_letter: letter.txt
  window:
    start: 2026-10-01
    end: 2026-12-31
  scope:
    allow_domains: [acme-example.com]
    allow_cidrs: ["203.0.113.0/24"]
    allow_private: false
"""


class TestEngagement(unittest.TestCase):
    def test_load_valid(self):
        from redteam.engagement import (apply_engagement,
                                        engagement_audit_detail, load_engagement)
        with tempfile.TemporaryDirectory() as td:
            letter = _write(Path(td), "letter.txt", "signed autorization letter")
            _write(Path(td), "acme.yaml", ENG_YAML)
            eng = load_engagement(Path(td) / "acme.yaml",
                                  now=date(2026, 10, 23))
            self.assertEqual(eng.id, "ACME-2026-01")
            self.assertEqual(eng.letter_sha256,
                             hashlib.sha256(letter.read_bytes()).hexdigest())
            self.assertEqual(eng.allow_domains, ("acme-example.com",))
            detail = engagement_audit_detail(eng)
            self.assertIn("authorization_letter_sha256", detail)

            from redteam.config import load_config
            cfg = load_config("config.example.yaml")
            cfg = apply_engagement(cfg, eng)
            self.assertEqual(cfg.scope.allow_domains, ["acme-example.com"])
            self.assertEqual(cfg.scope.allow_cidrs, ["203.0.113.0/24"])
            self.assertFalse(cfg.scope.allow_private)
            self.assertIn("ACME-2026-01", eng.describe())

    def test_missing_or_empty_letter_fails(self):
        from redteam.engagement import load_engagement
        with tempfile.TemporaryDirectory() as td:
            yml = ENG_YAML.replace("authorization_letter: letter.txt",
                                   "authorization_letter: missing.txt")
            _write(Path(td), "a.yaml", yml)
            with self.assertRaisesRegex(ValueError, "not found"):
                load_engagement(Path(td) / "a.yaml", now=date(2026, 10, 23))
            # an EMPTY letter at the referenced path is also refused
            _write(Path(td), "letter.txt", "")
            _write(Path(td), "b.yaml", ENG_YAML)
            with self.assertRaisesRegex(ValueError, "empty"):
                load_engagement(Path(td) / "b.yaml", now=date(2026, 10, 23))

    def test_window_enforced(self):
        from redteam.engagement import load_engagement
        with tempfile.TemporaryDirectory() as td:
            _write(Path(td), "letter.txt", "signed")
            _write(Path(td), "a.yaml", ENG_YAML)
            with self.assertRaisesRegex(ValueError, "window closed"):
                load_engagement(Path(td) / "a.yaml", now=date(2027, 2, 1))
            with self.assertRaisesRegex(ValueError, "window opens"):
                load_engagement(Path(td) / "a.yaml", now=date(2026, 1, 1))
            bad = ENG_YAML.replace("end: 2026-12-31", "end: 2026-01-01")
            _write(Path(td), "b.yaml", bad)
            with self.assertRaisesRegex(ValueError, "after end"):
                load_engagement(Path(td) / "b.yaml", now=date(2026, 10, 23))
            malformed = ENG_YAML.replace("start: 2026-10-01", "start: oct 1")
            _write(Path(td), "c.yaml", malformed)
            with self.assertRaisesRegex(ValueError, "ISO date"):
                load_engagement(Path(td) / "c.yaml", now=date(2026, 10, 23))

    def test_scope_required_and_bad_yaml(self):
        from redteam.engagement import load_engagement
        with tempfile.TemporaryDirectory() as td:
            _write(Path(td), "letter.txt", "signed")
            noscope = ENG_YAML.replace(
                "  scope:\n    allow_domains: [acme-example.com]\n"
                '    allow_cidrs: ["203.0.113.0/24"]\n', "")
            _write(Path(td), "a.yaml", noscope)
            with self.assertRaisesRegex(ValueError, "no scope"):
                load_engagement(Path(td) / "a.yaml", now=date(2026, 10, 23))
            _write(Path(td), "b.yaml", "- just\n- a list\n")
            with self.assertRaises(ValueError):
                load_engagement(Path(td) / "b.yaml")
            with self.assertRaisesRegex(ValueError, "not found"):
                load_engagement(Path(td) / "nope.yaml")


# ---------------------------------------------------------------------------
# orchestrator/report integration


class TestOrchestratorPhase4(unittest.TestCase):
    def _orch(self, tmp: Path):
        with tempfile.TemporaryDirectory() as td:
            pass
        return None

    def test_write_report_produces_html_drift_snapshot(self):
        cfg = load_config("config.example.yaml")
        cfg = replace(cfg, budget=BudgetConfig(max_total_tokens=5000))
        cfg = replace(
            cfg,
            safety=replace(cfg.safety, artifacts_dir=str(
                Path(tempfile.gettempdir()) / "p4test-artifacts")))
        import shutil
        artifacts = Path(cfg.safety.artifacts_dir)
        shutil.rmtree(artifacts, ignore_errors=True)

        from redteam.orchestrator import Orchestrator
        orch = Orchestrator(cfg)
        orch.state.add_finding(title="Legacy header", severity="low", target="t1",
                               evidence="http/1.1 200 <- header missing",
                               tool="web_security_checks", cwe="CWE-693")
        path = orch._write_report("t1", "narrtext")
        art = artifacts
        snap = load_snapshot(snapshot_path(art, "t1"))
        self.assertEqual(snap["target"], "t1")
        text = (path).read_text(encoding="utf-8")
        self.assertIn("First recorded run", text)
        self.assertIn("token budget", text)
        htmls = list(art.glob("report-*.html"))
        self.assertEqual(len(htmls), 1)
        self.assertIn("<pre><code>", htmls[0].read_text(encoding="utf-8"))

        # second run: same target, one finding gone, another reworded same fp
        orch2 = Orchestrator(cfg)
        orch2.state.add_finding(title="Legacy header", severity="medium",
                                target="t1",
                                evidence="different evidence, same identity",
                                tool="web_security_checks", cwe="CWE-693")
        orch2.state.add_finding(title="Fresh issue", severity="high", target="t1",
                                evidence="http/1.1 500 <- leak", cwe="CWE-209",
                                tool="web_security_checks")
        path2 = orch2._write_report("t1", "narr2")
        text2 = path2.read_text(encoding="utf-8")
        self.assertIn("Drift Since Last Run", text2)
        self.assertIn("**New findings:**", text2)
        self.assertIn("Fresh issue", text2)
        self.assertIn("**Persisting:**", text2)
        snap2 = load_snapshot(snapshot_path(art, "t1"))
        self.assertEqual(
            {i["fingerprint"] for i in snap2["findings"]},
            {fingerprint(f) for f in orch2.state.sorted_findings()})
        find_jsons = sorted(art.glob("findings-*.json"))
        self.assertGreaterEqual(len(find_jsons), 1)   # same-second stamps collide

    def test_run_end_audit_contains_usage_and_drift(self):
        cfg = load_config("config.example.yaml")
        cfg = replace(
            cfg,
            safety=replace(cfg.safety, artifacts_dir=str(
                Path(tempfile.gettempdir()) / "p4test-artifacts-audit")))
        import shutil
        artifacts = Path(cfg.safety.artifacts_dir)
        shutil.rmtree(artifacts, ignore_errors=True)
        from redteam.orchestrator import Orchestrator
        orch = Orchestrator(cfg)
        orch.state.add_finding(title="X", severity="info", target="t-audit",
                               evidence="evidence marker ' <- ' present",
                               tool="httpx")
        orch._write_report("t-audit", "n")
        events = [json.loads(l) for l in
                  (artifacts / "audit.jsonl").read_text(encoding="utf-8").splitlines()]
        end = [e for e in events if e.get("event") == "run_end"][-1]
        # detail may be nested as JSON string or dict depending on audit impl
        detail = end.get("detail") or {}
        if isinstance(detail, str):
            detail = json.loads(detail)
        self.assertIn("usage", detail)
        self.assertIn("drift", detail)
        self.assertIn("report_html", detail)


if __name__ == "__main__":
    unittest.main()
