"""Phase 1.3 — deterministic triage: evidence standards (confirmed requires
a request/response pair) and root-cause dedup clustering. All offline."""

from __future__ import annotations

import unittest

from redteam.report import render_report
from redteam.state import Finding, SharedState
from redteam.triage import (
    apply_evidence_standards,
    cluster_findings,
    evidence_supported,
)
from redteam.tools.base import ToolError
from redteam.tools.record import RecordFindingTool

CONF_EV = (
    "GET https://shop.test/login\n"
    "HTTP/1.1 200 OK\n"
    "Content-Security-Policy: <missing>"
)
CONFIRMED_EV = (
    "GET https://shop.test/api/user/7\n"
    "HTTP/1.1 200 OK\n"
    "response: {\"id\":7,\"email\":\"victim@shop.test\"}"
)


def F(title, target, severity="medium", status="suspected",
      evidence="", cwe="", cvss="", cves="", fid="F001"):
    return Finding(id=fid, title=title, severity=severity, target=target,
                   evidence=evidence, status=status, cwe=cwe, cvss=cvss, cves=cves)


class TestEvidenceStandard(unittest.TestCase):
    def test_response_artifact_is_supported(self):
        self.assertTrue(evidence_supported(F("t", "u", evidence=CONFIRMED_EV)))

    def test_bare_claim_is_not_supported(self):
        self.assertFalse(evidence_supported(
            F("t", "u", evidence="This endpoint is vulnerable to IDOR")))

    def test_too_short_evidence_is_not_supported(self):
        self.assertFalse(evidence_supported(F("t", "u", evidence="leaks data")))

    def test_confirmed_without_response_downgraded(self):
        f = F("IDOR", "https://s/api/7", status="confirmed",
              evidence="user 7 returned for the other account", cwe="CWE-639")
        [out] = apply_evidence_standards([f])
        self.assertEqual(out.status, "suspected")
        self.assertIn("evidence-standard", out.evidence)
        self.assertEqual(out.cwe, "CWE-639")  # preserved

    def test_confirmed_with_response_untouched(self):
        f = F("IDOR", "https://s/api/7", status="confirmed",
              evidence=CONFIRMED_EV)
        [out] = apply_evidence_standards([f])
        self.assertEqual(out.status, "confirmed")
        self.assertNotIn("evidence-standard", out.evidence)

    def test_suspected_never_touched(self):
        f = F("XSS", "https://s/q", status="suspected", evidence="")
        [out] = apply_evidence_standards([f])
        self.assertEqual(out.status, "suspected")
        self.assertEqual(out.evidence, "")


class TestRecordToolEnforcesEvidence(unittest.TestCase):
    def test_confirmed_without_pair_becomes_suspected(self):
        state = SharedState()
        tool = RecordFindingTool(state)
        res = tool.run({"title": "IDOR", "severity": "high",
                        "target": "https://s/api/7", "status": "confirmed",
                        "evidence": "returned victim data", "cwe": "CWE-639"})
        self.assertEqual(res.data["status"], "suspected")
        self.assertEqual(state.findings[0].status, "suspected")

    def test_confirmed_with_pair_stays_confirmed(self):
        state = SharedState()
        tool = RecordFindingTool(state)
        res = tool.run({"title": "IDOR", "severity": "high",
                        "target": "https://s/api/7", "status": "confirmed",
                        "evidence": CONFIRMED_EV})
        self.assertEqual(res.data["status"], "confirmed")


class TestClustering(unittest.TestCase):
    def test_same_cause_across_urls_clusters(self):
        fs = [
            F("Missing HSTS header", "https://a.test/", "medium", "confirmed",
              CONF_EV, cwe="CWE-319", fid="F001"),
            F("Missing HSTS header", "https://a.test/login", "medium",
              "confirmed", CONF_EV, cwe="CWE-319", fid="F002"),
            F("Missing HSTS header", "https://a.test/about", "low", "suspected",
              "", cwe="CWE-319", fid="F003"),
        ]
        clusters = cluster_findings(fs)
        self.assertEqual(len(clusters), 1)
        c = clusters[0]
        self.assertEqual(len(c.instance_targets), 3)
        self.assertEqual(c.finding.status, "confirmed")
        self.assertEqual(c.finding.severity, "medium")  # highest wins

    def test_different_titles_do_not_cluster(self):
        fs = [F("Missing HSTS", "https://a.test/", cwe="CWE-319"),
              F("Open CORS", "https://a.test/", cwe="CWE-942")]
        self.assertEqual(len(cluster_findings(fs)), 2)

    def test_same_title_different_cwe_do_not_cluster(self):
        fs = [F("Leaky endpoint", "https://a/", cwe="CWE-200"),
              F("Leaky endpoint", "https://a/b", cwe="CWE-639")]
        self.assertEqual(len(cluster_findings(fs)), 2)

    def test_title_wording_noise_is_normalized(self):
        fs = [F("The HSTS header is missing", "https://a/", cwe="CWE-319"),
              F("Missing HSTS header", "https://a/x", cwe="CWE-319")]
        self.assertEqual(len(cluster_findings(fs)), 1)

    def test_different_hosts_never_merge(self):
        """Cross-host merging would hide blast radius — must stay separate."""
        fs = [F("Missing HSTS", "https://a.test/", cwe="CWE-319"),
              F("Missing HSTS", "https://b.test/", cwe="CWE-319")]
        self.assertEqual(len(cluster_findings(fs)), 2)

    def test_same_host_same_title_clusters_with_all_instances(self):
        """One root cause on one host = one finding (nuclei dedup model);
        every instance URL stays individually listed in the report."""
        fs = [F("IDOR", "https://a/api/user/7", cwe="CWE-639"),
              F("IDOR", "https://a/api/order/9", cwe="CWE-639")]
        clusters = cluster_findings(fs)
        self.assertEqual(len(clusters), 1)
        self.assertEqual(clusters[0].instance_targets,
                         ["https://a/api/user/7", "https://a/api/order/9"])

    def test_same_host_same_title_different_query_clusters(self):
        fs = [F("XSS", "https://a/search?q=one", cwe="CWE-79"),
              F("XSS", "https://a/search?q=two", cwe="CWE-79")]
        self.assertEqual(len(cluster_findings(fs)), 1)

    def test_partial_confirmation_is_disclosed(self):
        fs = [
            F("Missing HSTS", "https://a/", status="confirmed",
              evidence=CONF_EV, cwe="CWE-319"),
            F("Missing HSTS", "https://a/x", status="suspected", cwe="CWE-319"),
        ]
        [c] = cluster_findings(fs)
        self.assertEqual(c.finding.status, "confirmed")
        self.assertEqual(c.confirmed_targets, ["https://a/"])
        self.assertFalse(c.confirmed_on_all)
        self.assertIn("demonstrated on 1 of 2", c.finding.evidence)


class TestReportRendering(unittest.TestCase):
    def test_report_shows_distinct_plus_instance_count(self):
        state = SharedState()
        for i, t in enumerate(["https://a.test/", "https://a.test/login",
                               "https://a.test/about"]):
            state.add_finding("Missing HSTS header", "medium", t,
                              evidence=CONF_EV, cwe="CWE-319", status="confirmed")
        md = render_report("a.test", "narrative", state)
        self.assertIn("1 distinct", md)
        self.assertIn("3 affected URL(s)", md)
        self.assertIn("Same root cause on 3 URL(s)", md)

    def test_report_flags_downgraded_confirmed(self):
        state = SharedState()
        state.add_finding("IDOR", "high", "https://a/api/7",
                          evidence="leaked victim", status="confirmed")
        md = render_report("a.test", "", state)
        self.assertIn("/ suspected]", md)
        self.assertIn("evidence-standard", md)

    def test_empty_findings_still_renders(self):
        md = render_report("a.test", "n", SharedState())
        self.assertIn("No findings were recorded", md)


if __name__ == "__main__":
    unittest.main()
