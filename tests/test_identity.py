"""Phase 2.1 — credential vault config + redaction pass.

Proves our own secrets cannot leak into the audit log, the findings store,
or the rendered report (Phase 2 exit criterion: zero credential leaks)."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

import yaml

from redteam.audit import AuditLog, verify_chain
from redteam.config import IDENTITY_KINDS, load_config
from redteam.redact import REDACTED, Redactor, redactor
from redteam.report import render_report
from redteam.state import SharedState

SECRET = "Sup3rS3cret-Passw0rd!"
TOKEN = "eyJhbGciOiJIUzI1NiJ9.abcd.efgh"


def base_config(extra: dict) -> str:
    raw = {
        "llm": {
            "hosted": {"provider": "openai_compatible",
                       "base_url": "https://api.example.com/v1",
                       "api_key_env": "K", "model": "m"},
            "local": {"provider": "openai_compatible",
                      "base_url": "http://localhost:11434/v1",
                      "api_key_env": "O", "model": "m"},
        },
        "scope": {"allow_domains": ["localhost"]},
        "safety": {"artifacts_dir": tempfile.mkdtemp()},
    }
    raw.update(extra)
    p = Path(tempfile.mkdtemp()) / "cfg.yaml"
    p.write_text(yaml.safe_dump(raw), encoding="utf-8")
    return str(p)


class TestRedactor(unittest.TestCase):
    def setUp(self):
        redactor.clear()

    def tearDown(self):
        redactor.clear()

    def test_scrub_replaces_registered_secret(self):
        redactor.register(SECRET)
        text = f"login failed for password={SECRET} try again"
        out = redactor.scrub(text)
        self.assertNotIn(SECRET, out)
        self.assertIn(REDACTED, out)

    def test_longest_secret_replaced_first(self):
        redactor.register("password123")
        redactor.register("password123456")
        out = redactor.scrub("x password123456 y")
        self.assertNotIn("password123", out.replace(REDACTED, ""))

    def test_short_values_not_registered(self):
        redactor.register("abc")
        self.assertEqual(redactor.count, 0)
        self.assertEqual(redactor.scrub("abc def"), "abc def")

    def test_none_and_empty_ignored(self):
        redactor.register(None)
        redactor.register("")
        self.assertEqual(redactor.count, 0)

    def test_scrub_obj_deep(self):
        redactor.register(SECRET)
        obj = {"a": [f"hdr: {SECRET}", {"b": SECRET}], "n": 5}
        out = redactor.scrub_obj(obj)
        self.assertNotIn(SECRET, json.dumps(out))
        self.assertEqual(out["n"], 5)  # non-strings untouched

    def test_fresh_instance_starts_empty(self):
        self.assertEqual(Redactor().count, 0)


class TestAuditRedaction(unittest.TestCase):
    def setUp(self):
        redactor.clear()

    def tearDown(self):
        redactor.clear()

    def test_secret_never_hits_audit_file(self):
        redactor.register(SECRET)
        path = Path(tempfile.mkdtemp()) / "audit.jsonl"
        log = AuditLog(path)
        log.record("login_attempt", actor="session_manager",
                   detail={"password": SECRET, "note": f"sent {SECRET}"})
        raw = path.read_text(encoding="utf-8")
        self.assertNotIn(SECRET, raw)
        self.assertIn(REDACTED, raw)
        ok, msg = verify_chain(path)  # scrubbing happens before hashing
        self.assertTrue(ok, msg)

    def test_chain_verifies_after_scrub(self):
        redactor.register(SECRET)
        path = Path(tempfile.mkdtemp()) / "audit.jsonl"
        log = AuditLog(path)
        log.record("a", detail={"k": SECRET})
        log.record("b", target=f"https://t/?token={SECRET}")
        ok, _ = verify_chain(path)
        self.assertTrue(ok)


class TestFindingAndReportRedaction(unittest.TestCase):
    def setUp(self):
        redactor.clear()

    def tearDown(self):
        redactor.clear()

    def test_secret_stripped_from_finding_evidence(self):
        redactor.register(SECRET)
        state = SharedState()
        f = state.add_finding(
            "Login reflects password", "high", "https://t/login",
            evidence=f"request body: password={SECRET}", status="confirmed",
        )
        self.assertNotIn(SECRET, f.evidence)
        self.assertIn(REDACTED, f.evidence)

    def test_secret_stripped_from_report(self):
        redactor.register(SECRET)
        redactor.register(TOKEN)
        state = SharedState()
        state.add_finding("X", "low", "https://t/",
                          evidence=f"cookie session={TOKEN}")
        md = render_report("t", f"operator note: password is {SECRET}", state)
        self.assertNotIn(SECRET, md)
        self.assertNotIn(TOKEN, md)
        self.assertIn(REDACTED, md)


class TestIdentityConfig(unittest.TestCase):
    def _identities(self, identities: list):
        cfg = load_config(base_config({"identities": identities}))
        return cfg.identities

    def test_no_identities_by_default(self):
        self.assertEqual(load_config(base_config({})).identities, [])

    def test_form_identity_parsed(self):
        [ident] = self._identities([{
            "name": "alice", "kind": "form",
            "login_url": "https://t/login",
            "username_env": "ALICE_USER", "password_env": "ALICE_PASS",
            "username_field": "email", "password_field": "password",
            "verify_url": "https://t/api/me", "verify_marker": "alice@",
        }])
        self.assertEqual(ident.kind, "form")
        self.assertEqual(ident.username_env, "ALICE_USER")
        self.assertEqual(ident.verify_marker, "alice@")

    def test_cookie_identity(self):
        [ident] = self._identities([{"name": "s", "kind": "cookie",
                                     "cookie_env": "S_COOKIE"}])
        self.assertEqual(ident.cookie_env, "S_COOKIE")

    def test_bearer_identity(self):
        [ident] = self._identities([{"name": "b", "kind": "bearer",
                                     "token_env": "B_TOKEN"}])
        self.assertEqual(ident.kind, "bearer")

    def test_apikey_default_header(self):
        [ident] = self._identities([{"name": "k", "kind": "apikey",
                                     "token_env": "K_TOKEN"}])
        self.assertEqual(ident.header_name, "X-API-Key")

    def test_all_kinds_documented(self):
        self.assertEqual(set(IDENTITY_KINDS), {"form", "cookie", "bearer", "apikey"})

    def test_missing_name_rejected(self):
        with self.assertRaises(ValueError):
            self._identities([{"kind": "cookie", "cookie_env": "X"}])

    def test_unknown_kind_rejected(self):
        with self.assertRaises(ValueError) as cm:
            self._identities([{"name": "x", "kind": "oauth"}])
        self.assertIn("kind", str(cm.exception))

    def test_form_missing_fields_rejected(self):
        with self.assertRaises(ValueError) as cm:
            self._identities([{"name": "x", "kind": "form",
                               "login_url": "https://t/login"}])
        self.assertIn("username_env", str(cm.exception))

    def test_form_requires_http_url(self):
        with self.assertRaises(ValueError):
            self._identities([{"name": "x", "kind": "form",
                               "login_url": "ftp://t/login",
                               "username_env": "U", "password_env": "P"}])

    def test_cookie_missing_env_rejected(self):
        with self.assertRaises(ValueError):
            self._identities([{"name": "x", "kind": "cookie"}])

    def test_bearer_missing_token_rejected(self):
        with self.assertRaises(ValueError):
            self._identities([{"name": "x", "kind": "bearer"}])

    def test_verify_needs_both_halves(self):
        with self.assertRaises(ValueError):
            self._identities([{"name": "x", "kind": "cookie",
                               "cookie_env": "C",
                               "verify_url": "https://t/me"}])

    def test_duplicate_names_rejected(self):
        with self.assertRaises(ValueError) as cm:
            self._identities([{"name": "x", "kind": "cookie", "cookie_env": "A"},
                              {"name": "x", "kind": "cookie", "cookie_env": "B"}])
        self.assertIn("duplicate", str(cm.exception))

    def test_config_file_never_holds_secret_values(self):
        """Config carries env VAR NAMES only — an audit of the example file
        must never contain password/token values."""
        root = Path(__file__).resolve().parent.parent
        text = (root / "config.example.yaml").read_text(encoding="utf-8")
        for marker in ("password:", "secret:", "token:", "cookie:"):
            self.assertNotIn(marker, text.lower())


if __name__ == "__main__":
    unittest.main()
