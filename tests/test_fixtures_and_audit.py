"""Fixture-layer guarantees: replay is hard-offline, record is transparent.
Also covers audit chain tamper scenarios and resume behavior."""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from redteam.audit import AuditLog, verify_chain
from redteam.fixtures import FixtureManager, FixtureProvider, FixtureTool
from redteam.llm import Provider
from redteam.tools.base import Tool, ToolResult


class ExplodingTool(Tool):
    name = "exploding"
    description = "must never run in replay"
    parameters = {"type": "object", "properties": {}}

    def run(self, args):
        raise AssertionError("real tool executed during replay!")


class ExplodingProvider(Provider):
    model = "exploding-model"

    def complete(self, system, messages):
        raise AssertionError("real LLM called during replay!")


class TestReplayOffline(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())

    def _record(self):
        fx = FixtureManager(self.tmp / "cass", "record")

        class SafeTool(Tool):
            name, description = "exploding", "recording stand-in"
            parameters = {"type": "object", "properties": {}}

            def run(self, args):
                return ToolResult(ok=True, summary="recorded-output")

        tool = FixtureTool(SafeTool(), fx)
        tool.run({})
        class SafeProvider(Provider):
            model = "exploding-model"

            def complete(self, system, messages):
                return '{"action": "final", "answer": "recorded"}'

        out = FixtureProvider(SafeProvider(), fx).complete("sys", [])
        fx.save()
        return out

    def test_replay_hits_never_touch_real_impl(self):
        self._record()
        fx = FixtureManager(self.tmp / "cass", "replay")
        provider = FixtureProvider(ExplodingProvider(), fx)
        text = provider.complete("sys", [])  # would raise if it reached the model
        self.assertIn("recorded", text)
        tool = FixtureTool(ExplodingTool(), fx)
        result = tool.run({})  # would raise if it executed
        self.assertEqual(result.summary, "recorded-output")
        self.assertEqual(fx.counts["fixture_misses"], 0)

    def test_replay_miss_stays_offline(self):
        self._record()
        fx = FixtureManager(self.tmp / "cass", "replay")
        result = FixtureTool(ExplodingTool(), fx).run({"unseen": "args"})
        self.assertIn("FIXTURE MISS", result.summary)
        provider = FixtureProvider(ExplodingProvider(), fx)
        text = provider.complete("different system", [])
        self.assertIn("FIXTURE MISS", text)
        self.assertEqual(fx.counts["fixture_misses"], 2)

    def test_live_mode_counts_but_never_reads_cassettes(self):
        fx = FixtureManager(self.tmp / "cass", "live")
        class CountingTool(Tool):
            name, description = "exploding", "x"
            parameters = {"type": "object", "properties": {}}
            def run(self, args):
                return ToolResult(ok=True, summary="live-run")
        result = FixtureTool(CountingTool(), fx).run({})
        self.assertEqual(result.summary, "live-run")
        self.assertEqual(fx.counts["tool_calls"], 1)
        fx.save()  # live mode must not write cassettes
        self.assertFalse((self.tmp / "cass" / "tools.json").exists())


class TestAuditChain(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.path = self.tmp / "audit.jsonl"
        self.audit = AuditLog(self.path)
        for i in range(5):
            self.audit.record("tool_call", actor="test", target=f"h{i}.example")

    def _lines(self):
        return self.path.read_text(encoding="utf-8").splitlines()

    def test_intact_chain_verifies(self):
        ok, msg = verify_chain(self.path)
        self.assertTrue(ok, msg)

    def test_edit_detected(self):
        lines = self._lines()
        e = json.loads(lines[2])
        e["target"] = "tampered.example"
        lines[2] = json.dumps(e)
        self.path.write_text("\n".join(lines), encoding="utf-8")
        ok, msg = verify_chain(self.path)
        self.assertFalse(ok)
        self.assertIn("hash mismatch", msg)

    def test_reorder_detected(self):
        lines = self._lines()
        lines[1], lines[3] = lines[3], lines[1]
        self.path.write_text("\n".join(lines), encoding="utf-8")
        ok, msg = verify_chain(self.path)
        self.assertFalse(ok)
        self.assertIn("prev_hash", msg)

    def test_tail_truncation_limitation_documented(self):
        # Truncating the tail leaves a valid prefix — detectable only by an
        # external count/anchor. Verify this behavior so nobody assumes more.
        lines = self._lines()
        self.path.write_text("\n".join(lines[:-1]), encoding="utf-8")
        ok, _ = verify_chain(self.path)
        self.assertTrue(ok)  # prefix is valid; tail loss needs external anchoring

    def test_resume_continues_chain(self):
        second = AuditLog(self.path)  # reopen: must continue, not restart
        second.record("run_end", actor="test")
        ok, msg = verify_chain(self.path)
        self.assertTrue(ok, msg)
        seqs = [json.loads(l)["seq"] for l in self._lines()]
        self.assertEqual(seqs, list(range(1, len(seqs) + 1)))


if __name__ == "__main__":
    unittest.main()
