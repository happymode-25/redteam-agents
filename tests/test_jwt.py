"""Phase 2.2 — JWT static checks.

Crafts real HMAC-signed tokens with stdlib (hmac/hashlib/base64) and
verifies every verdict branch of jwt_verdict(), plus tool-level checks
(provenance/evidence markers, redaction, wiring).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import tempfile
import time
import unittest
from dataclasses import replace
from pathlib import Path

from redteam.config import load_config
from redteam.redact import redactor
from redteam.tools.base import ToolError
from redteam.tools.jwt import (JwtCheckTool, b64url_encode, header_issues,
                               jwt_verdict, parse_jwt, verify_weak_secret)

NOW = 1_700_000_000.0


def craft(header: dict, claims: dict, secret: str | None = None) -> str:
    h = b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    c = b64url_encode(json.dumps(claims, separators=(",", ":")).encode())
    signing_input = f"{h}.{c}"
    if secret is None:
        return signing_input + "."
    sig = b64url_encode(
        hmac.new(secret.encode(), signing_input.encode(),
                 hashlib.sha256).digest())
    return f"{signing_input}.{sig}"


def hs256(claims: dict, secret: str = "secret") -> str:
    return craft({"alg": "HS256", "typ": "JWT"}, claims, secret)


class TestVerdictBranches(unittest.TestCase):
    def test_weak_secret_is_confirmed(self):
        token = hs256({"sub": "1", "exp": NOW + 3600})
        header, claims, sig = parse_jwt(token)
        weak = verify_weak_secret(f"{token.split('.')[0]}.{token.split('.')[1]}",
                                  sig, "HS256")
        self.assertEqual(weak, "secret")
        v = jwt_verdict(header, claims, weak, now=NOW)
        self.assertEqual(v["verdict"], "confirmed")
        self.assertEqual(v["cwe"], "CWE-798")

    def test_uncommon_secret_passes(self):
        token = hs256({"sub": "1", "exp": NOW + 3600},
                      secret="Xk7#vQ2mZp9LwR4t")
        parts = token.split(".")
        weak = verify_weak_secret(f"{parts[0]}.{parts[1]}", parts[2], "HS256")
        self.assertIsNone(weak)
        header, claims, _ = parse_jwt(token)
        v = jwt_verdict(header, claims, weak, now=NOW)
        self.assertEqual(v["verdict"], "no_issue")

    def test_alg_none_is_suspected(self):
        token = craft({"alg": "none", "typ": "JWT"}, {"sub": "1", "exp": NOW + 60})
        header, claims, _ = parse_jwt(token)
        v = jwt_verdict(header, claims, None, now=NOW)
        self.assertEqual(v["verdict"], "suspected")
        self.assertEqual(v["cwe"], "CWE-347")
        self.assertIn("NOT tested", v["reason"])

    def test_missing_exp_is_suspected(self):
        header, claims, _ = parse_jwt(hs256({"sub": "1"}))
        v = jwt_verdict(header, claims, None, now=NOW)
        self.assertEqual(v["verdict"], "suspected")
        self.assertEqual(v["cwe"], "CWE-613")

    def test_sensitive_claim_is_confirmed(self):
        header, claims, _ = parse_jwt(
            hs256({"sub": "1", "password": "hunter2", "exp": NOW + 3600}))
        v = jwt_verdict(header, claims, None, now=NOW)
        self.assertEqual(v["verdict"], "confirmed")
        self.assertEqual(v["cwe"], "CWE-200")
        self.assertIn("password", v["sensitive_claims"])

    def test_nested_sensitive_claim(self):
        header, claims, _ = parse_jwt(
            hs256({"user": {"card": {"creditCardNumber": "411111"}},
                   "exp": NOW + 3600}))
        v = jwt_verdict(header, claims, None, now=NOW)
        self.assertEqual(v["verdict"], "confirmed")

    def test_long_lived_is_suspected(self):
        header, claims, _ = parse_jwt(
            hs256({"sub": "1", "exp": NOW + 90 * 86400}))
        v = jwt_verdict(header, claims, None, now=NOW)
        self.assertEqual(v["verdict"], "suspected")
        self.assertEqual(v["cwe"], "CWE-613")
        self.assertGreater(v["remaining_days"], 30)

    def test_expired_is_no_issue_with_pointer(self):
        header, claims, _ = parse_jwt(
            hs256({"sub": "1", "exp": NOW - 86400}))
        v = jwt_verdict(header, claims, None, now=NOW)
        self.assertEqual(v["verdict"], "no_issue")
        self.assertTrue(v["expired"])
        self.assertIn("session tools", v["reason"])

    def test_rs256_structure_only(self):
        token = craft({"alg": "RS256", "typ": "JWT"},
                      {"sub": "1", "exp": NOW + 3600})
        header, claims, _ = parse_jwt(token)
        v = jwt_verdict(header, claims, None, now=NOW)
        self.assertEqual(v["verdict"], "no_issue")
        self.assertIn("not verifiable locally", v["reason"])

    def test_weak_secret_skipped_for_asymmetric(self):
        # RS256 signature must not be treated as HMAC material
        self.assertIsNone(verify_weak_secret("a.b", "c3ln", "RS256"))


class TestParsing(unittest.TestCase):
    def test_bearer_prefix_stripped(self):
        tok = hs256({"sub": "1", "exp": NOW + 60})
        header, claims, sig = parse_jwt(f"Bearer {tok}")
        self.assertEqual(header["alg"], "HS256")
        self.assertTrue(sig)

    def test_wrong_segment_count_rejected(self):
        with self.assertRaises(ToolError):
            parse_jwt("just-a-string")
        with self.assertRaises(ToolError):
            parse_jwt("a.b.c.d")

    def test_non_json_claims_rejected(self):
        h = b64url_encode(b'{"alg":"HS256"}')
        c = b64url_encode(b'"just-a-string"')
        with self.assertRaises(ToolError):
            parse_jwt(f"{h}.{c}.")


class TestJwtTool(unittest.TestCase):
    def test_confirmed_with_provenance_marker(self):
        redactor.clear()
        self.addCleanup(redactor.clear)
        token = hs256({"sub": "1", "exp": NOW + 3600})
        tool = JwtCheckTool()
        res = tool.run({"token": token, "source": "login response body"})
        self.assertEqual(res.data["verdict"], "confirmed")
        self.assertIn("CWE-798", res.data["recommendation"])
        # evidence provenance must satisfy the confirmed-evidence standard
        self.assertIn("response:", res.data["evidence"])
        self.assertNotIn("secret'", "")  # sanity
        self.assertNotIn(token, res.data["evidence"])  # sig never persisted

    def test_missing_source_drops_provenance(self):
        token = hs256({"sub": "1", "exp": NOW + 3600})
        res = JwtCheckTool().run({"token": token})
        self.assertIn("NOT provided", res.data["evidence"])
        self.assertNotIn("response:", res.data["evidence"])

    def test_empty_token_is_tool_error(self):
        with self.assertRaises(ToolError):
            JwtCheckTool().run({"token": ""})

    def test_evidence_redacts_registered_secrets(self):
        redactor.clear()
        self.addCleanup(redactor.clear)
        redactor.register("Sup3rS3cret-Value")
        token = hs256({"note": "Sup3rS3cret-Value", "exp": NOW + 3600})
        res = JwtCheckTool().run({"token": token, "source": "somewhere"})
        self.assertNotIn("Sup3rS3cret-Value", res.data["evidence"])

    def test_registered_in_orchestrator(self):
        root = Path(__file__).resolve().parent.parent
        cfg = load_config(root / "config.example.yaml")
        tmp = Path(tempfile.mkdtemp())
        cfg = replace(cfg, safety=replace(
            cfg.safety, artifacts_dir=str(tmp / "art"),
            cassette_dir=str(tmp / "cass"), runner="local"))
        from redteam.orchestrator import Orchestrator
        orch = Orchestrator(cfg)
        self.assertIsNotNone(orch.registry.get("jwt_check"))


class TestKeyControlAndKid(unittest.TestCase):
    """2.3 — token-controlled key material and kid injection patterns are
    flagged as *suspected* (static signal only: server-side acceptance is
    never tested by a static check)."""

    def _verdict(self, header: dict, claims: dict | None = None,
                 secret: str | None = None) -> dict:
        claims = {"sub": "1", "exp": NOW + 3600} if claims is None else claims
        token = craft(header, claims, secret)
        h, c, sig = parse_jwt(token)
        signing_input = ".".join(token.split(".")[:2])
        weak = (verify_weak_secret(signing_input, sig, h.get("alg", ""))
                if sig else None)
        return jwt_verdict(h, c, weak, now=NOW)

    def test_kid_path_traversal_is_suspected(self):
        v = self._verdict({"alg": "HS256", "typ": "JWT",
                           "kid": "../../etc/passwd"})
        self.assertEqual(v["verdict"], "suspected")
        self.assertEqual(v["cwe"], "CWE-22")
        self.assertIn("traversal", v["reason"].lower())
        self.assertTrue(v["header_issues"])

    def test_kid_sql_metacharacters_is_suspected(self):
        v = self._verdict({"alg": "HS256", "typ": "JWT", "kid": "admin'--"})
        self.assertEqual(v["verdict"], "suspected")
        self.assertEqual(v["cwe"], "CWE-89")

    def test_embedded_jwk_is_suspected(self):
        v = self._verdict({"alg": "RS256", "typ": "JWT",
                           "jwk": {"kty": "RSA", "n": "AAAA"}})
        self.assertEqual(v["verdict"], "suspected")
        self.assertEqual(v["cwe"], "CWE-347")
        self.assertIn("embeds its own verification key", v["reason"])

    def test_jku_url_is_suspected(self):
        v = self._verdict({"alg": "RS256", "typ": "JWT",
                           "jku": "https://attacker.example/jwks.json"})
        self.assertEqual(v["verdict"], "suspected")
        self.assertIn("jku", v["reason"])

    def test_x5c_is_suspected(self):
        v = self._verdict({"alg": "RS256", "typ": "JWT", "x5c": ["MIIB..."]})
        self.assertEqual(v["verdict"], "suspected")
        self.assertEqual(v["cwe"], "CWE-347")

    def test_clean_kid_is_not_flagged(self):
        v = self._verdict({"alg": "HS256", "typ": "JWT",
                           "kid": "2f9a1c7e-5b3d-4a11-9c02-abcdef012345"})
        self.assertEqual(v["verdict"], "no_issue")
        self.assertEqual(v["header_issues"], [])

    def test_weak_secret_outranks_header_issues(self):
        v = self._verdict({"alg": "HS256", "typ": "JWT",
                           "kid": "../../etc/passwd"}, secret="secret")
        self.assertEqual(v["verdict"], "confirmed")
        self.assertEqual(v["cwe"], "CWE-798")

    def test_header_issues_helper_is_pure(self):
        issues = header_issues({"jwk": {}, "kid": "a'--"})
        kinds = " ".join(text for text, _ in issues)
        self.assertIn("jwk", kinds)
        self.assertIn("SQL", kinds)
        self.assertEqual(header_issues({}), [])

    def test_tool_evidence_lists_header_issues(self):
        token = craft({"alg": "HS256", "typ": "JWT", "kid": "../../x"},
                      {"sub": "1", "exp": NOW + 3600}, None)
        res = JwtCheckTool().run({"token": token, "source": "cookie"})
        self.assertEqual(res.data["verdict"], "suspected")
        self.assertIn("header_issues", res.data["evidence"])


if __name__ == "__main__":
    unittest.main()
