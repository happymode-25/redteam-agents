"""Adversarial scope-escape suite (ROADMAP Phase 0).

Every attack an LLM or a malicious redirect chain could try against the
scope boundary: redirect escapes, DNS rebinding, IP/host obfuscation,
userinfo tricks, IDN homographs, kill-switch behavior, audit coverage.

Runs fully offline: a local HTTP server provides redirect chains, and DNS
behavior is simulated with getaddrinfo patches. No external traffic.
"""

from __future__ import annotations

import json
import socket
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from unittest import mock

import sys
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from redteam.audit import AuditLog, verify_chain
from redteam.config import ScopeConfig
from redteam.http import ScopedHttpError, ScopedSession
from redteam.scope import (
    Guard, KillSwitch, KillSwitchEngaged, RateLimiter, ScopeViolation,
    host_from_target,
)


class RedirectHandler(BaseHTTPRequestHandler):
    """Redirect chains for escape/loop tests."""

    def do_GET(self):
        routes = {
            "/escape": (302, "http://evil.invalid/steal"),
            "/escape-private": (302, "http://10.9.8.7/latest/meta-data/"),
            "/escape-ip": (302, "http://8.8.4.4/"),
            "/chain": (302, "/hop2"),
            "/loop": (302, "/loop"),
        }
        if self.path in routes:
            code, location = routes[self.path]
            self.send_response(code)
            self.send_header("Location", location)
            self.end_headers()
        elif self.path in ("/hop2", "/ok"):
            body = b"final destination"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, *args):
        pass


def make_guard(domains=("localhost",), cidrs=(), allow_private=True, audit=None,
               tmpdir=None) -> Guard:
    return Guard(
        cfg=ScopeConfig(
            allow_domains=list(domains),
            allow_cidrs=list(cidrs),
            allow_private=allow_private,
            rate_limit_per_host_per_min=0,
        ),
        kill=KillSwitch(Path(tmpdir or tempfile.mkdtemp()) / "K"),
        limiter=RateLimiter(0),
        audit=audit,
    )


class TestRedirectEscape(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = HTTPServer(("127.0.0.1", 0), RedirectHandler)
        cls.port = cls.server.server_address[1]
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def session(self, guard) -> ScopedSession:
        return ScopedSession(guard, timeout=5, max_redirects=4)

    def test_in_scope_chain_followed(self):
        s = self.session(make_guard())
        resp = s.get(f"http://localhost:{self.port}/chain")
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(resp.url.endswith("/hop2"))
        self.assertEqual(len(resp.history), 1)

    def test_redirect_to_out_of_scope_host_blocked(self):
        s = self.session(make_guard())
        with self.assertRaises(ScopeViolation):
            s.get(f"http://localhost:{self.port}/escape")

    def test_redirect_to_unlisted_ip_blocked(self):
        # 10.9.8.7 is private AND outside any allowlisted CIDR
        s = self.session(make_guard(cidrs=["203.0.113.0/24"], allow_private=True))
        with self.assertRaises(ScopeViolation):
            s.get(f"http://localhost:{self.port}/escape-private")

    def test_redirect_to_public_ip_outside_cidr_blocked(self):
        s = self.session(make_guard(cidrs=["203.0.113.0/24"], allow_private=True))
        with self.assertRaises(ScopeViolation):
            s.get(f"http://localhost:{self.port}/escape-ip")

    def test_redirect_loop_hits_cap_not_hang(self):
        s = self.session(make_guard())
        with self.assertRaises(ScopedHttpError):
            s.get(f"http://localhost:{self.port}/loop")

    def test_kill_switch_stops_mid_chain(self):
        guard = make_guard()
        s = self.session(guard)
        guard.kill.trip()
        with self.assertRaises(KillSwitchEngaged):
            s.get(f"http://localhost:{self.port}/ok")


class TestHostObfuscation(unittest.TestCase):
    def test_decimal_ip_not_treated_as_scope_ip(self):
        # http://2130706433/ is 127.0.0.1 in decimal; must not pass as an IP
        host = host_from_target("http://2130706433/")
        g = make_guard(domains=["example.com"], cidrs=["203.0.113.0/24"],
                       allow_private=False)
        with self.assertRaises(ScopeViolation):
            g.authorize(host)
        with self.assertRaises(ScopeViolation):
            g.authorize("http://2130706433/")

    def test_userinfo_trick(self):
        # authority is evil.com; 'example.com' is only userinfo
        self.assertEqual(host_from_target("https://example.com@evil.com/"), "evil.com")

    def test_suffix_attacks(self):
        g = make_guard(domains=["example.com"], allow_private=False)
        for bad in ("example.com.evil.net", "notexample.com", "example.com-evil.net",
                    "evilexample.com", "example.com.attacker"):
            with self.assertRaises(ScopeViolation, msg=bad):
                g.authorize(bad)

    def test_trailing_dot_fqdn_is_normalized(self):
        g = make_guard(domains=["example.com"], allow_private=False)
        self.assertEqual(g.authorize("example.com."), "example.com")
        self.assertEqual(host_from_target("https://EXAMPLE.COM./path"), "example.com")

    def test_homograph_denied(self):
        g = make_guard(domains=["example.com"], allow_private=False)
        with self.assertRaises(ScopeViolation):
            g.authorize("еxample.com")  # cyrillic 'е'

    def test_idn_normalized_to_punycode_both_sides(self):
        g = make_guard(domains=["münchen.example"], allow_private=False)
        self.assertEqual(g.authorize("https://münchen.example/"), "xn--mnchen-3ya.example")
        self.assertEqual(g.authorize("https://xn--mnchen-3ya.example/"),
                         "xn--mnchen-3ya.example")

    def test_private_ipv6_blocked(self):
        g = make_guard(cidrs=["fd00::/8"], allow_private=False)
        with self.assertRaises(ScopeViolation):
            g.authorize("[fd00::1]")
        g2 = make_guard(cidrs=["fd00::/8"], allow_private=True)
        self.assertEqual(g2.authorize("[fd00::1]"), "fd00::1")

    def test_malformed_targets_raise_scope_violation_not_crash(self):
        for bad in ("http://", "://x", "[unterminated", "", "   ", ".."):
            with self.assertRaises(ScopeViolation, msg=repr(bad)):
                host_from_target(bad)


class TestDnsRebinding(unittest.TestCase):
    def test_private_answer_rejected(self):
        # 'rebind.example.com' is in the domain allowlist but resolves private
        def fake_getaddrinfo(node, port, *a, **kw):
            if node == "rebind.example.com":
                return [(socket.AF_INET, socket.SOCK_STREAM, 6, "",
                         ("127.0.0.1", port or 0))]
            raise socket.gaierror(-2, "not found")

        g = make_guard(domains=["example.com"], allow_private=False)
        with mock.patch("socket.getaddrinfo", side_effect=fake_getaddrinfo):
            with self.assertRaises(ScopeViolation) as ctx:
                g.resolve("rebind.example.com")
        self.assertIn("rebinding", str(ctx.exception))

    def test_mixed_answer_picks_global(self):
        def fake_getaddrinfo(node, port, *a, **kw):
            return [
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", port or 0)),
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port or 0)),
            ]

        g = make_guard(domains=["example.com"], allow_private=False)
        with mock.patch("socket.getaddrinfo", side_effect=fake_getaddrinfo):
            self.assertEqual(g.resolve("example.com"), "93.184.216.34")


class TestAuditCoverage(unittest.TestCase):
    def test_denials_and_resolutions_audited(self):
        tmp = Path(tempfile.mkdtemp())
        audit = AuditLog(tmp / "audit.jsonl")
        g = make_guard(domains=["example.com"], cidrs=["203.0.113.0/24"],
                       allow_private=False, audit=audit)
        g.authorize("example.com")
        with self.assertRaises(ScopeViolation):
            g.authorize("evil.com")
        with mock.patch("socket.getaddrinfo",
                        side_effect=lambda *a, **k: [
                            (socket.AF_INET, 6, 6, "", ("127.0.0.1", 0))]):
            with self.assertRaises(ScopeViolation):
                g.resolve("example.com")

        ok, msg = verify_chain(tmp / "audit.jsonl")
        self.assertTrue(ok, msg)
        events = [json.loads(l) for l in
                  (tmp / "audit.jsonl").read_text().splitlines()]
        names = {e["event"] for e in events}
        self.assertIn("scope_allowed", names)
        self.assertIn("scope_denied", names)
        self.assertIn("resolve_denied", names)
        denied = [e for e in events if e["event"] == "scope_denied"]
        self.assertEqual(denied[0]["target"], "evil.com")


if __name__ == "__main__":
    unittest.main()
