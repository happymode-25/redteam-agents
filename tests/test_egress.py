"""Step-N egress firewall: policy checks, socket patches, lifecycle, config.

Zero-network guarantee: every test either (a) exercises the policy methods
directly, (b) swaps the module-level _ORIGINAL_* callables for in-process
recorders, or (c) uses a real socket only against loopback / against a
destination the patch REFUSES before any packet can leave. The one test
that reaches a real connect uses a listener bound on 127.0.0.1.

Only allowlisted-path tests use genuinely public IPs (93.184.216.0/24,
example.com's block) so the suite behaves identically on every Python
version — older interpreters classify TEST-NET ranges as private, which
would flip an allow_private=False test.
"""

from __future__ import annotations

import json
import socket
import tempfile
import types
import unittest
from dataclasses import replace
from pathlib import Path
from unittest import mock
from urllib.parse import urlparse

from redteam.audit import AuditLog
from redteam.config import load_config
from redteam.egress import (DEFAULT_TTL, EgressFirewall, EgressViolation,
                            active, set_audit)
from redteam.http import _pinned_resolution
from redteam.scope import ScopeViolation
from redteam.tools.cve_lookup import (EPSS_ENDPOINT, KEV_FEED,
                                      NVD_ENDPOINT)

ROOT = Path(__file__).resolve().parent.parent
INTEL_HOSTS = {urlparse(u).hostname for u in (NVD_ENDPOINT, KEV_FEED,
                                              EPSS_ENDPOINT)} - {None}

SCOPE_IP = "93.184.216.34"      # inside the default test CIDR, public
OUT_IP = "198.51.100.9"         # TEST-NET-2: outside every test allowlist


class FakeSock:
    """Minimal socket stand-in: only the attributes the patches read."""
    family = socket.AF_INET


class FakeLocalSock:
    """Any non-INET/INET6 family exercises the 'not IP egress' guard.
    (1 == AF_UNIX on POSIX; this Windows build doesn't expose AF_UNIX.)"""
    family = 1


def make_fw(**overrides) -> EgressFirewall:
    base = dict(
        scope_domains=["shop.test"],
        allow_cidrs=["93.184.216.0/24"],
        allow_subdomains=True,
        allow_private=False,
    )
    base.update(overrides)
    return EgressFirewall(**base)


def fake_addrinfo(answers, calls=None):
    """Stand-in for the original getaddrinfo: canned answers, call log."""
    def fake(node, port, *args, **kwargs):
        if calls is not None:
            calls.append(node)
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, port or 0))
                for ip in answers]
    return fake


def recorder(store):
    def rec(sock, *args, **kwargs):
        store.append(args)
        return 0
    return rec


class TestViolationSemantics(unittest.TestCase):
    def test_egress_violation_is_a_scope_violation(self):
        self.assertTrue(issubclass(EgressViolation, ScopeViolation))

    def test_handler_catching_scope_violation_sees_egress(self):
        fw = make_fw()
        with self.assertRaises(ScopeViolation):
            fw.check_host("evil.example")


class TestHostPolicy(unittest.TestCase):
    def test_allows_exact_scope_domain(self):
        self.assertEqual(make_fw().check_host("shop.test"), "shop.test")

    def test_allows_subdomain_by_default(self):
        self.assertEqual(make_fw().check_host("api.shop.test"),
                         "api.shop.test")

    def test_rejects_subdomain_when_disabled(self):
        fw = make_fw(allow_subdomains=False)
        with self.assertRaises(EgressViolation):
            fw.check_host("api.shop.test")

    def test_rejects_suffix_spoof(self):
        # "evilshop.test" merely ENDs with "shop.test" — not a subdomain.
        with self.assertRaises(EgressViolation):
            make_fw().check_host("evilshop.test")

    def test_rejects_out_of_scope_host(self):
        with self.assertRaises(EgressViolation):
            make_fw().check_host("evil.example")

    def test_normalizes_case_and_trailing_dot(self):
        self.assertEqual(make_fw().check_host("Shop.TEST."), "shop.test")

    def test_idn_input_matches_punycode_scope_entry(self):
        fw = make_fw(scope_domains=["münchen.example"])
        self.assertEqual(fw.check_host("MÜNCHEN.EXAMPLE."),
                         "xn--mnchen-3ya.example")

    def test_extra_host_allowed(self):
        fw = make_fw(extra_hosts={"api.openai.com"})
        self.assertEqual(fw.check_host("api.openai.com"), "api.openai.com")

    def test_extra_host_normalized_at_construction(self):
        fw = make_fw(extra_hosts={"API.Example.COM."})
        self.assertEqual(fw.check_host("api.example.com"), "api.example.com")

    def test_extra_ip_literal_routes_to_ip_policy(self):
        fw = make_fw(extra_hosts={"127.0.0.1"})
        self.assertEqual(fw.check_host("127.0.0.1"), "127.0.0.1")

    def test_empty_host_refused(self):
        with self.assertRaises(EgressViolation):
            make_fw().check_host("")


class TestIpPolicy(unittest.TestCase):
    def test_allows_ip_inside_scope_cidr(self):
        make_fw().check_ip(SCOPE_IP)          # no raise

    def test_blocks_ip_outside_every_cidr(self):
        with self.assertRaises(EgressViolation):
            make_fw().check_ip(OUT_IP)

    def test_cidr_match_does_not_license_private_when_forbidden(self):
        fw = make_fw(allow_cidrs=["10.0.0.0/8"], allow_private=False)
        with self.assertRaises(EgressViolation):
            fw.check_ip("10.5.5.5")

    def test_private_allowed_when_operator_opted_in(self):
        make_fw(allow_cidrs=["10.0.0.0/8"],
                allow_private=True).check_ip("10.5.5.5")

    def test_loopback_gate(self):
        with self.assertRaises(EgressViolation):
            make_fw(allow_cidrs=["127.0.0.0/8"],
                    allow_private=False).check_ip("127.0.0.1")
        make_fw(allow_cidrs=["127.0.0.0/8"],
                allow_private=True).check_ip("127.0.0.1")

    def test_cached_ip_allowed_outside_cidrs(self):
        fw = make_fw()
        fw._cache({OUT_IP})                   # as if just resolved for a
        fw.check_ip(OUT_IP)                   # scoped hostname: now allowed
        with self.assertRaises(EgressViolation):
            fw.check_ip("192.0.2.7")          # never cached → blocked

    def test_cache_expires_after_ttl(self):
        t = [1000.0]
        fw = make_fw(clock=lambda: t[0])
        fw._cache({OUT_IP})
        fw.check_ip(OUT_IP)                   # inside TTL → allowed
        t[0] = 1000.0 + DEFAULT_TTL + 1
        with self.assertRaises(EgressViolation):
            fw.check_ip(OUT_IP)               # expired → blocked

    def test_extra_ip_literal_allowed(self):
        make_fw(extra_hosts={"127.0.0.1"}).check_ip("127.0.0.1")

    def test_ipv6_extra_literal_allowed(self):
        make_fw(extra_hosts={"::1"}).check_ip("::1")

    def test_unparseable_ip_refused(self):
        with self.assertRaises(EgressViolation):
            make_fw().check_ip("not-an-ip")


class TestUsable(unittest.TestCase):
    def test_private_answers_filtered_for_scope_hosts(self):
        fw = make_fw()
        self.assertEqual(fw._usable("shop.test",
                                    ["10.0.0.1", SCOPE_IP, "garbage"]),
                         [SCOPE_IP])

    def test_private_answers_kept_for_extra_hosts(self):
        fw = make_fw(extra_hosts={"llm.local"})
        self.assertEqual(fw._usable("llm.local", ["10.0.0.1"]), ["10.0.0.1"])

    def test_private_answers_kept_when_allow_private(self):
        fw = make_fw(allow_private=True)
        self.assertEqual(fw._usable("shop.test", ["10.0.0.1"]),
                         ["10.0.0.1"])

    def test_unparseable_answers_skipped(self):
        fw = make_fw()
        self.assertEqual(fw._usable("shop.test", ["garbage"]), [])


class TestCheckConnect(unittest.TestCase):
    def test_ip_literal_in_cidr_returns_itself(self):
        self.assertEqual(make_fw().check_connect(SCOPE_IP), SCOPE_IP)

    def test_ip_literal_outside_blocks(self):
        with self.assertRaises(EgressViolation):
            make_fw().check_connect(OUT_IP)

    def test_hostname_resolves_caches_and_returns_verified_ip(self):
        fw = make_fw()
        with mock.patch("redteam.egress._ORIGINAL_GETADDRINFO",
                        fake_addrinfo([SCOPE_IP])):
            self.assertEqual(fw.check_connect("shop.test"), SCOPE_IP)
        fw.check_ip(SCOPE_IP)                 # now cached

    def test_hostname_all_private_answers_blocked(self):
        fw = make_fw()
        with mock.patch("redteam.egress._ORIGINAL_GETADDRINFO",
                        fake_addrinfo(["10.9.9.9"])):
            with self.assertRaises(EgressViolation):
                fw.check_connect("shop.test")

    def test_hostname_outside_policy_never_resolved(self):
        calls = []
        fw = make_fw()
        with mock.patch("redteam.egress._ORIGINAL_GETADDRINFO",
                        fake_addrinfo([SCOPE_IP], calls)):
            with self.assertRaises(EgressViolation):
                fw.check_connect("evil.example")
        self.assertEqual(calls, [])


class TestPatchedGetaddrinfo(unittest.TestCase):
    def test_blocks_hostname_before_dns_query(self):
        calls = []
        fw = make_fw()
        with mock.patch("redteam.egress._ORIGINAL_GETADDRINFO",
                        fake_addrinfo([SCOPE_IP], calls)):
            with self.assertRaises(EgressViolation):
                fw._patched_getaddrinfo("evil.example", 80)
        self.assertEqual(calls, [])

    def test_allows_scope_hostname_and_caches(self):
        fw = make_fw()
        with mock.patch("redteam.egress._ORIGINAL_GETADDRINFO",
                        fake_addrinfo([SCOPE_IP])):
            infos = fw._patched_getaddrinfo("shop.test", 443)
        self.assertEqual(infos[0][4][0], SCOPE_IP)
        fw.check_ip(SCOPE_IP)                 # cached from the resolution

    def test_ip_literal_passes_unchecked_and_uncached(self):
        # By design: getaddrinfo also serves bind(); connect() is the
        # enforcement point for numeric destinations.
        fw = make_fw()
        with mock.patch("redteam.egress._ORIGINAL_GETADDRINFO",
                        fake_addrinfo([OUT_IP])):
            infos = fw._patched_getaddrinfo(OUT_IP, 80)
        self.assertEqual(infos[0][4][0], OUT_IP)
        with self.assertRaises(EgressViolation):
            fw.check_ip(OUT_IP)               # not cached by the lookup

    def test_none_node_passes(self):
        fw = make_fw()
        with mock.patch("redteam.egress._ORIGINAL_GETADDRINFO",
                        fake_addrinfo(["0.0.0.0"])):
            fw._patched_getaddrinfo(None, 80, flags=0x1)  # AI_PASSIVE shape

    def test_bytes_hostname_checked(self):
        fw = make_fw()
        with self.assertRaises(EgressViolation):
            fw._patched_getaddrinfo(b"evil.example", 80)


class TestPatchedConnect(unittest.TestCase):
    def test_blocks_out_of_scope_ip_before_syscall(self):
        sent = []
        fw = make_fw()
        with mock.patch("redteam.egress._ORIGINAL_CONNECT", recorder(sent)):
            with self.assertRaises(EgressViolation):
                fw._patched_connect(FakeSock(), (OUT_IP, 80))
        self.assertEqual(sent, [])

    def test_allows_ip_in_cidr(self):
        sent = []
        fw = make_fw()
        with mock.patch("redteam.egress._ORIGINAL_CONNECT", recorder(sent)):
            fw._patched_connect(FakeSock(), (SCOPE_IP, 443))
        self.assertEqual(sent, [((SCOPE_IP, 443),)])

    def test_hostname_address_rewritten_to_verified_ip(self):
        sent = []
        fw = make_fw()
        with mock.patch("redteam.egress._ORIGINAL_GETADDRINFO",
                        fake_addrinfo([SCOPE_IP])), \
             mock.patch("redteam.egress._ORIGINAL_CONNECT", recorder(sent)):
            fw._patched_connect(FakeSock(), ("shop.test", 443))
        self.assertEqual(sent, [((SCOPE_IP, 443),)])

    def test_non_ip_family_passes_through(self):
        sent = []
        fw = make_fw()
        with mock.patch("redteam.egress._ORIGINAL_CONNECT", recorder(sent)):
            fw._patched_connect(FakeLocalSock(), "/tmp/ipc.sock")
        self.assertEqual(sent, [("/tmp/ipc.sock",)])

    def test_non_tuple_address_passes_to_cpython(self):
        sent = []
        fw = make_fw()
        with mock.patch("redteam.egress._ORIGINAL_CONNECT", recorder(sent)):
            fw._patched_connect(FakeSock(), 2)  # raw-fd shape; CPython raises
        self.assertEqual(sent, [(2,)])

    def test_connect_ex_blocked_before_syscall(self):
        sent = []
        fw = make_fw()
        with mock.patch("redteam.egress._ORIGINAL_CONNECT_EX", recorder(sent)):
            with self.assertRaises(EgressViolation):
                fw._patched_connect_ex(FakeSock(), (OUT_IP, 80))
        self.assertEqual(sent, [])

    def test_connect_ex_rewrites_hostname(self):
        sent = []
        fw = make_fw()
        with mock.patch("redteam.egress._ORIGINAL_GETADDRINFO",
                        fake_addrinfo([SCOPE_IP])), \
             mock.patch("redteam.egress._ORIGINAL_CONNECT_EX", recorder(sent)):
            fw._patched_connect_ex(FakeSock(), ("shop.test", 22))
        self.assertEqual(sent, [((SCOPE_IP, 22),)])


class TestPatchedSendto(unittest.TestCase):
    def test_blocks_unauthorized_udp_target(self):
        sent = []
        fw = make_fw()
        with mock.patch("redteam.egress._ORIGINAL_SENDTO", recorder(sent)):
            with self.assertRaises(EgressViolation):
                fw._patched_sendto(FakeSock(), b"x", (OUT_IP, 53))
        self.assertEqual(sent, [])

    def test_allows_authorized_udp_target(self):
        sent = []
        fw = make_fw()
        with mock.patch("redteam.egress._ORIGINAL_SENDTO", recorder(sent)):
            fw._patched_sendto(FakeSock(), b"x", (SCOPE_IP, 53))
        self.assertEqual(sent, [(b"x", (SCOPE_IP, 53))])

    def test_zero_args_no_indexerror(self):
        sent = []
        fw = make_fw()
        with mock.patch("redteam.egress._ORIGINAL_SENDTO", recorder(sent)):
            fw._patched_sendto(FakeSock())     # CPython would raise TypeError
        self.assertEqual(sent, [()])

    def test_non_ip_family_and_non_tuple_pass(self):
        sent = []
        fw = make_fw()
        with mock.patch("redteam.egress._ORIGINAL_SENDTO", recorder(sent)):
            fw._patched_sendto(FakeLocalSock(), b"x", "/tmp/udp.sock")
            fw._patched_sendto(FakeSock(), b"x", "not-a-sockaddr")
        self.assertEqual(len(sent), 2)


class TestGethostbyname(unittest.TestCase):
    def test_blocks_hostname_before_query(self):
        calls = []
        fw = make_fw()

        def rec(host):
            calls.append(host)
            return SCOPE_IP

        with mock.patch("redteam.egress._ORIGINAL_GETHOSTBYNAME", rec):
            with self.assertRaises(EgressViolation):
                fw._patched_gethostbyname("evil.example")
        self.assertEqual(calls, [])

    def test_ex_caches_answers(self):
        fw = make_fw()
        with mock.patch("redteam.egress._ORIGINAL_GETHOSTBYNAME_EX",
                        lambda h: (h, [], ["10.0.0.5", SCOPE_IP])):
            fw._patched_gethostbyname_ex("shop.test")
        fw.check_ip(SCOPE_IP)                 # public answer cached
        with self.assertRaises(EgressViolation):
            fw.check_ip("10.0.0.5")           # private answer filtered out


class TestLifecycle(unittest.TestCase):
    def snapshot(self):
        return {
            "getaddrinfo": socket.getaddrinfo,
            "gethostbyname": socket.gethostbyname,
            "gethostbyname_ex": socket.gethostbyname_ex,
            "connect": socket.socket.connect,
            "connect_ex": socket.socket.connect_ex,
            "sendto": socket.socket.sendto,
        }

    def test_install_patches_all_six_slots(self):
        before = self.snapshot()
        fw = make_fw()
        fw.install()
        self.addCleanup(fw.uninstall)
        self.assertIsNot(socket.getaddrinfo, before["getaddrinfo"])
        self.assertIsNot(socket.socket.connect, before["connect"])
        # The class-level patches must be PLAIN functions (a bound method
        # stored on the class would not re-bind to the socket instance).
        self.assertIsInstance(socket.socket.connect, types.FunctionType)
        self.assertIsInstance(socket.socket.sendto, types.FunctionType)
        # Module-level patches are bound methods of the firewall.
        self.assertIsInstance(socket.getaddrinfo, types.MethodType)

    def test_uninstall_restores_original_identities(self):
        before = self.snapshot()
        fw = make_fw()
        fw.install()
        fw.uninstall()
        after = self.snapshot()
        for key in before:
            self.assertIs(after[key], before[key], key)

    def test_install_is_idempotent(self):
        fw = make_fw()
        self.assertEqual(fw.install(), "installed")
        self.addCleanup(fw.uninstall)
        self.assertEqual(fw.install(), "already installed")

    def test_uninstall_when_never_installed_is_noop(self):
        before = self.snapshot()
        make_fw().uninstall()
        after = self.snapshot()
        for key in before:
            self.assertIs(after[key], before[key], key)

    def test_second_install_hands_over_cleanly(self):
        before = self.snapshot()
        a = make_fw()
        a.install()
        self.addCleanup(a.uninstall)
        b = make_fw()
        b.install()
        self.addCleanup(b.uninstall)
        self.assertFalse(a._installed)
        self.assertIs(active(), b)
        self.assertIs(socket.getaddrinfo, b._patched["getaddrinfo"])
        b.uninstall()
        after = self.snapshot()
        for key in before:
            self.assertIs(after[key], before[key], key)

    def test_uninstall_never_clobbers_a_foreign_slot(self):
        fw = make_fw()
        fw.install()
        self.addCleanup(fw.uninstall)
        foreign = lambda *a, **k: []           # noqa: E731 — stand-in patch
        socket.getaddrinfo = foreign
        fw.uninstall()                         # skips the occupied slot
        self.assertIs(socket.getaddrinfo, foreign)
        socket.getaddrinfo = fw._originals["getaddrinfo"]  # manual restore

    def test_context_manager_installs_and_uninstalls(self):
        before = socket.getaddrinfo
        with make_fw() as fw:
            self.assertIs(active(), fw)
            with self.assertRaises(EgressViolation):
                socket.getaddrinfo("evil.example", 80)  # policy: no DNS sent
        self.assertIsNone(active())
        self.assertIs(socket.getaddrinfo, before)

    def test_active_and_set_audit(self):
        self.assertIsNone(active())
        fw = make_fw()
        fw.install()
        self.addCleanup(fw.uninstall)
        self.assertIs(active(), fw)
        log = AuditLog(Path(tempfile.mkdtemp()) / "audit.jsonl")
        set_audit(log)
        self.assertIs(fw.audit, log)
        set_audit(None)
        self.assertIsNone(fw.audit)

    def test_set_audit_with_no_firewall_is_noop(self):
        set_audit(AuditLog(Path(tempfile.mkdtemp()) / "audit.jsonl"))

    def test_real_socket_connect_refused_before_any_packet(self):
        fw = make_fw()
        fw.install()
        self.addCleanup(fw.uninstall)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.addCleanup(sock.close)
        with self.assertRaises(EgressViolation):
            sock.connect((OUT_IP, 80))         # patch raises before syscall

    def test_real_socket_connect_ex_refused_before_any_packet(self):
        fw = make_fw()
        fw.install()
        self.addCleanup(fw.uninstall)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.addCleanup(sock.close)
        with self.assertRaises(EgressViolation):
            sock.connect_ex((OUT_IP, 80))

    def test_real_loopback_connect_allowed_when_opted_in(self):
        fw = make_fw(allow_cidrs=["127.0.0.0/8"], allow_private=True)
        fw.install()
        self.addCleanup(fw.uninstall)
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.addCleanup(listener.close)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.addCleanup(client.close)
        client.settimeout(5)
        client.connect(("127.0.0.1", listener.getsockname()[1]))
        conn, _ = listener.accept()
        conn.close()


class TestAudit(unittest.TestCase):
    def test_blocks_are_recorded(self):
        tmp = Path(tempfile.mkdtemp())
        log = AuditLog(tmp / "audit.jsonl")
        fw = make_fw(audit=log)
        with self.assertRaises(EgressViolation):
            fw.check_host("evil.example")
        entries = [json.loads(line) for line in
                   (tmp / "audit.jsonl").read_text("utf-8").splitlines()]
        self.assertEqual(entries[-1]["event"], "egress_blocked")
        self.assertEqual(entries[-1]["decision"], "denied")
        self.assertIn("evil.example", entries[-1]["target"])


class TestPinComposition(unittest.TestCase):
    def test_http_pin_wraps_the_active_firewall_patch(self):
        # The request pin captures socket.getaddrinfo at entry — with the
        # firewall installed first it captures the firewall's patch, and on
        # exit restores it (never the stale original).
        fw = make_fw()
        fw.install()
        self.addCleanup(fw.uninstall)
        with _pinned_resolution("shop.test", SCOPE_IP):
            infos = socket.getaddrinfo("shop.test", 80,
                                       type=socket.SOCK_STREAM)
            self.assertEqual(infos[0][4][0], SCOPE_IP)
        self.assertIs(socket.getaddrinfo, fw._patched["getaddrinfo"])


class TestFromConfig(unittest.TestCase):
    def load_example(self):
        return load_config(ROOT / "config.example.yaml")

    def build(self, cfg):
        with mock.patch("redteam.egress.getproxies", return_value={}):
            return EgressFirewall.from_config(cfg)

    def test_scope_mapping(self):
        cfg = self.load_example()
        fw = self.build(cfg)
        self.assertEqual(fw.scope_domains, list(cfg.scope.allow_domains))
        self.assertEqual([str(n) for n in fw.networks],
                         list(cfg.scope.allow_cidrs))
        self.assertEqual(fw.allow_subdomains, cfg.scope.allow_subdomains)
        self.assertEqual(fw.allow_private, cfg.scope.allow_private)

    def test_llm_backends_always_allowed(self):
        fw = self.build(self.load_example())
        self.assertIn("api.openai.com", fw.extra_hosts)   # hosted
        self.assertIn("localhost", fw.extra_hosts)        # local Ollama
        fw.check_host("api.openai.com")
        fw.check_host("localhost")

    def test_intel_enabled_includes_feeds(self):
        fw = self.build(self.load_example())
        self.assertTrue(INTEL_HOSTS <= fw.extra_hosts, fw.extra_hosts)
        for host in INTEL_HOSTS:
            fw.check_host(host)

    def test_intel_disabled_drops_feed_hosts(self):
        cfg = self.load_example()
        cfg = replace(cfg, intel=replace(cfg.intel, enabled=False))
        fw = self.build(cfg)
        self.assertFalse(INTEL_HOSTS & fw.extra_hosts)

    def test_proxy_hosts_included_when_configured(self):
        cfg = self.load_example()
        with mock.patch("redteam.egress.getproxies",
                        return_value={"https": "http://proxy.corp:3128"}):
            fw = EgressFirewall.from_config(cfg)
        self.assertIn("proxy.corp", fw.extra_hosts)

    def test_invalid_cidr_refused_at_construction(self):
        with self.assertRaises(EgressViolation):
            make_fw(allow_cidrs=["not-a-cidr"])

    def test_invalid_cidr_from_config_refused(self):
        cfg = self.load_example()
        cfg = replace(cfg, scope=replace(cfg.scope, allow_cidrs=["bogus"]))
        with self.assertRaises(EgressViolation):
            self.build(cfg)

    def test_describe_summarizes_policy(self):
        fw = make_fw(extra_hosts={"localhost"})
        text = fw.describe()
        self.assertIn("shop.test", text)
        self.assertIn("93.184.216.0/24", text)
        self.assertIn("localhost", text)


if __name__ == "__main__":
    unittest.main()
