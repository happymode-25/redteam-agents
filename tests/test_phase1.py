"""Phase 1 depth tools: parsers, scope filtering, intel lookups, wiring.

All offline: binaries are never executed (parsers take text), third-party
intel APIs are mocked, and no target traffic occurs.
"""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import yaml

from redteam.config import IntelConfig, load_config
from redteam.scope import Guard, KillSwitch, RateLimiter, ScopeConfig
from redteam.tools.api_discovery import parse_openapi_spec
from redteam.tools.base import ToolError
from redteam.tools.cve_lookup import CveLookupTool, KEV_FEED
from redteam.tools.ffuf import parse_ffuf_json
from redteam.tools.katana import filter_in_scope, parse_katana_jsonl


def make_guard(domains=("localhost",), cidrs=(), allow_private=True) -> Guard:
    return Guard(
        cfg=ScopeConfig(allow_domains=list(domains), allow_cidrs=list(cidrs),
                        allow_private=allow_private, rate_limit_per_host_per_min=0),
        kill=KillSwitch(Path(tempfile.mkdtemp()) / "K"),
        limiter=RateLimiter(0),
    )


class TestKatanaParsing(unittest.TestCase):
    def test_jsonl_parse_tolerates_noise(self):
        text = "\n".join([
            '[INF] some banner line',
            json.dumps({"timestamp": "t", "request": {"method": "GET"},
                        "response": {"status_code": 200}}),  # no "url" field
            json.dumps({"url": "https://example.com/a"}),
            "not json at all",
            json.dumps({"url": "ftp://example.com/x"}),      # non-http skipped
            json.dumps({"url": "https://example.com/b"}),
        ])
        self.assertEqual(parse_katana_jsonl(text),
                         ["https://example.com/a", "https://example.com/b"])

    def test_empty_and_garbage(self):
        self.assertEqual(parse_katana_jsonl(""), [])
        self.assertEqual(parse_katana_jsonl("{broken json"), [])

    def test_filter_in_scope_drops_and_dedups(self):
        guard = make_guard(domains=["example.com"], allow_private=False)
        urls = [
            "https://example.com/a",
            "https://example.com/a",              # duplicate
            "https://evil.invalid/steal",         # out of scope
            "https://example.com.evil.net/",      # suffix attack
            "https://sub.example.com/b",          # in scope (subdomains on)
        ]
        in_scope, dropped = filter_in_scope(urls, guard)
        self.assertEqual(in_scope,
                         ["https://example.com/a", "https://sub.example.com/b"])
        self.assertEqual(dropped, 2)

    def test_filter_allows_private_when_configured(self):
        guard = make_guard(domains=["localhost"], allow_private=True)
        in_scope, dropped = filter_in_scope(["http://localhost:3000/x"], guard)
        self.assertEqual(len(in_scope), 1)
        self.assertEqual(dropped, 0)


class TestFfufParsing(unittest.TestCase):
    def test_results_document_shape(self):
        doc = {"results": [
            {"url": "http://t/admin", "status": 200, "length": 431,
             "words": 50, "input": {"FUZZ": "admin"}},
            {"url": "http://t/.git/HEAD", "status": 403, "length": 12,
             "words": 3, "input": {"FUZZ": ".git/HEAD"}},
        ], "config": {}}
        out = parse_ffuf_json(json.dumps(doc))
        self.assertEqual(len(out), 2)
        self.assertEqual(out[0]["fuzz"], "admin")
        self.assertEqual(out[1]["status"], 403)

    def test_list_shape_and_ndjson_fallback(self):
        self.assertEqual(len(parse_ffuf_json('[{"url": "x", "status": 200}]')), 1)
        ndjson = '{"url": "a", "status": 200}\n{"url": "b", "status": 404}\n'
        self.assertEqual(len(parse_ffuf_json(ndjson)), 2)
        self.assertEqual(parse_ffuf_json("total garbage"), [])


class TestOpenApiParsing(unittest.TestCase):
    def test_openapi3_spec_summary(self):
        spec = {
            "openapi": "3.0.1",
            "info": {"title": "Demo API", "version": "1.2"},
            "servers": [{"url": "https://api.example.com"}],
            "paths": {
                "/users": {"get": {"security": []}, "post": {}},
                "/health": {"get": {"security": [{"apiKey": []}]}},
            },
            "components": {"securitySchemes": {"apiKey": {"type": "apiKey"}}},
        }
        out = parse_openapi_spec(spec)
        self.assertTrue(out["valid"])
        self.assertEqual(out["title"], "Demo API")
        self.assertEqual(out["path_count"], 2)
        self.assertEqual(out["auth_schemes"], ["apiKey"])
        self.assertIn("/users", out["paths_without_security"])
        self.assertNotIn("/health", out["paths_without_security"])

    def test_swagger2_and_invalid(self):
        s2 = {"swagger": "2.0", "info": {"title": "Legacy", "version": "1"},
              "paths": {}, "securityDefinitions": {"basic": {"type": "basic"}}}
        out = parse_openapi_spec(s2)
        self.assertTrue(out["valid"])
        self.assertEqual(out["auth_schemes"], ["basic"])
        self.assertFalse(parse_openapi_spec({"random": 1})["valid"])
        self.assertFalse(parse_openapi_spec([])["valid"])  # type: ignore[arg-type]


NVD_PAYLOAD = {
    "totalResults": 2,
    "vulnerabilities": [
        {"cve": {
            "id": "CVE-2024-0001",
            "published": "2024-03-01T00:00:00.000",
            "descriptions": [{"lang": "en", "value": "RCE in foo parser"}],
            "metrics": {"cvssMetricV31": [{"cvssData": {
                "baseScore": 9.8,
                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}}]},
            "weaknesses": [{"description": [{"lang": "en", "value": "CWE-502"}]}],
        }},
        {"cve": {
            "id": "CVE-2024-0002",
            "descriptions": [{"lang": "en", "value": "XSS"}],
            "metrics": {},
        }},
    ],
}
KEV_PAYLOAD = {"vulnerabilities": [
    {"cveID": "CVE-2024-0001", "ransomwareCampaignUse": "Known",
     "dueDate": "2024-04-01", "product": "foo"},
]}
EPSS_PAYLOAD = {"data": [
    {"cve": "CVE-2024-0001", "epss": "0.8512", "percentile": "0.991"},
    {"cve": "CVE-2024-0002", "epss": "0.0103", "percentile": "0.412"},
]}


class TestCveLookup(unittest.TestCase):
    def setUp(self):
        self.cache = Path(tempfile.mkdtemp())
        self.tool = CveLookupTool(IntelConfig(enabled=True), self.cache)
        self.calls: list[str] = []

        def fake_get(url, **kw):
            self.calls.append(url)
            resp = mock.Mock()
            resp.raise_for_status = lambda: None
            if "nvd.nist.gov" in url:
                resp.json = lambda: NVD_PAYLOAD
            elif "cisa.gov" in url:
                resp.json = lambda: KEV_PAYLOAD
            elif "first.org" in url:
                resp.json = lambda: EPSS_PAYLOAD
            else:
                raise AssertionError(f"unexpected URL: {url}")
            return resp

        patcher = mock.patch("redteam.tools.cve_lookup.requests.get",
                             side_effect=fake_get)
        sleep_patcher = mock.patch("redteam.tools.cve_lookup.time.sleep")
        self.addCleanup(patcher.stop)
        self.addCleanup(sleep_patcher.stop)
        patcher.start()
        sleep_patcher.start()

    def test_full_lookup_annotates_kev_and_epss(self):
        result = self.tool.run({"product": "foo", "version": "1.2.3"})
        self.assertTrue(result.ok)
        matches = {m["cve"]: m for m in result.data["matches"]}
        self.assertEqual(set(matches), {"CVE-2024-0001", "CVE-2024-0002"})
        m1 = matches["CVE-2024-0001"]
        self.assertTrue(m1["kev"])
        self.assertEqual(m1["cvss"], 9.8)
        self.assertIn("CWE-502", m1["cwes"])
        self.assertEqual(m1["epss"]["epss"], "0.8512")
        self.assertEqual(m1["kev_detail"]["dueDate"], "2024-04-01")
        self.assertFalse(matches["CVE-2024-0002"]["kev"])
        self.assertIn("2 CVE match(es) (1 in CISA KEV)", result.summary)

    def test_feeds_cached_across_runs(self):
        self.tool.run({"product": "foo"})
        n_calls_first = len(self.calls)
        self.tool.run({"product": "foo"})
        # second run: only NVD again; KEV + EPSS served from disk
        self.assertEqual(len(self.calls), n_calls_first + 1)
        self.assertTrue((self.cache / "kev.json").exists())

    def test_intel_disabled_never_touches_network(self):
        tool = CveLookupTool(IntelConfig(enabled=False), self.cache)
        result = tool.run({"product": "foo"})
        self.assertTrue(result.ok)
        self.assertTrue(result.data["disabled"])
        self.assertEqual(self.calls, [])

    def test_no_matches_is_clean_result(self):
        empty = {"totalResults": 0, "vulnerabilities": []}
        with mock.patch("redteam.tools.cve_lookup.requests.get") as g:
            resp = mock.Mock()
            resp.raise_for_status = lambda: None
            resp.json = lambda: empty
            g.return_value = resp
            result = self.tool.run({"product": "nothing"})
        self.assertIn("no CVE matches", result.summary)
        # only the NVD query went out — no KEV/EPSS fetch without candidates
        self.assertEqual(g.call_count, 1)

    def test_nvd_failure_raises_tool_error(self):
        import requests
        with mock.patch("redteam.tools.cve_lookup.requests.get",
                        side_effect=requests.exceptions.ConnectionError("down")):
            with self.assertRaises(ToolError):
                self.tool.run({"product": "foo"})


class TestConfigIntel(unittest.TestCase):
    def _base(self) -> dict:
        return {
            "llm": {
                "hosted": {"provider": "openai_compatible",
                           "base_url": "https://api.openai.com/v1",
                           "api_key_env": "K", "model": "m"},
                "local": {"provider": "openai_compatible",
                          "base_url": "http://localhost:11434/v1",
                          "api_key_env": "", "model": "local"},
            },
        }

    def _load(self, raw) -> "object":
        p = Path(tempfile.mkdtemp()) / "c.yaml"
        p.write_text(yaml.safe_dump(raw), encoding="utf-8")
        return load_config(p)

    def test_intel_defaults_on_when_section_missing(self):
        cfg = self._load(self._base())
        self.assertTrue(cfg.intel.enabled)
        self.assertEqual(cfg.intel.cache_ttl_hours, 24)

    def test_intel_section_parsed(self):
        raw = self._base()
        raw["intel"] = {"enabled": False, "cache_ttl_hours": 6,
                        "nvd_api_key_env": "NVD_KEY"}
        cfg = self._load(raw)
        self.assertFalse(cfg.intel.enabled)
        self.assertEqual(cfg.intel.cache_ttl_hours, 6)
        self.assertEqual(cfg.intel.nvd_api_key_env, "NVD_KEY")


class TestWiring(unittest.TestCase):
    """The orchestrator must expose every Phase 0/1 tool to the agents."""

    def test_all_tools_registered(self):
        from redteam.orchestrator import Orchestrator

        root = Path(__file__).resolve().parent.parent
        cfg = load_config(root / "config.example.yaml")
        tmp = Path(tempfile.mkdtemp())
        cfg = replace(cfg, safety=replace(
            cfg.safety,
            artifacts_dir=str(tmp / "art"),
            cassette_dir=str(tmp / "cass"),
            runner="local",
        ))
        orch = Orchestrator(cfg)
        expected = {
            "subdomain_enum", "web_probe", "nmap_scan", "nuclei_scan",
            "web_security_checks", "tls_check", "email_auth_check",
            "http_request", "record_finding",
            # Phase 1
            "katana_scan", "content_discovery", "api_discovery", "cve_lookup",
        }
        missing = [n for n in expected if orch.registry.get(n) is None]
        self.assertEqual(missing, [], f"tools not registered: {missing}")

    def test_example_config_loads_with_new_sections(self):
        root = Path(__file__).resolve().parent.parent
        cfg = load_config(root / "config.example.yaml")
        self.assertIsInstance(cfg.intel, IntelConfig)
        self.assertTrue(cfg.intel.enabled)


if __name__ == "__main__":
    unittest.main()
