"""Lab server smoke tests: every planted vulnerability the eval truth
scores must actually be observable, or the truth file is lying.

In-process server on an ephemeral loopback port; zero external deps
beyond requests. Also asserts the loopback-only bind refusal (the lab
must never be reachable off-host).
"""

from __future__ import annotations

import sys
import threading
import unittest
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "lab"))

import vulnserver  # noqa: E402


class LabServerTest(unittest.TestCase):
    server = None
    base = ""

    @classmethod
    def setUpClass(cls):
        vulnserver.prepare_files()      # data/ dir + vault, as main() would
        cls.server = vulnserver.ThreadingHTTPServer(
            ("127.0.0.1", 0), vulnserver.LabHandler)
        cls.base = f"http://127.0.0.1:{cls.server.server_address[1]}"
        cls.thread = threading.Thread(target=cls.server.serve_forever,
                                      daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    # ------------------------------------------------------------ headers etc
    def test_index_lists_directory(self):
        r = requests.get(f"{self.base}/", timeout=5)
        self.assertEqual(r.status_code, 200)
        self.assertIn("index of /", r.text[:4096].lower())

    def test_security_headers_absent(self):
        r = requests.get(f"{self.base}/login", timeout=5)
        for header in ("Content-Security-Policy", "X-Frame-Options",
                       "X-Content-Type-Options", "Referrer-Policy",
                       "Strict-Transport-Security"):
            self.assertNotIn(header, r.headers, header)

    def test_version_disclosure_present(self):
        r = requests.get(f"{self.base}/", timeout=5)
        self.assertIn("Server", r.headers)
        self.assertIn("python", r.headers["Server"].lower())
        self.assertEqual(r.headers.get("X-Powered-By"), "PHP/7.4.3")

    def test_cors_reflects_origin_with_credentials(self):
        r = requests.get(f"{self.base}/",
                         headers={"Origin": "https://redteam-probe.invalid"},
                         timeout=5)
        self.assertEqual(r.headers.get("Access-Control-Allow-Origin"),
                         "https://redteam-probe.invalid")
        self.assertEqual(r.headers.get("Access-Control-Allow-Credentials"),
                         "true")

    def test_insecure_cookie_on_login_get(self):
        r = requests.get(f"{self.base}/login", timeout=5)
        cookie = r.headers.get("Set-Cookie", "")
        self.assertIn("session=", cookie)
        self.assertNotIn("httponly", cookie.lower())
        self.assertNotIn("samesite", cookie.lower())

    def test_dangerous_methods_advertised(self):
        r = requests.options(f"{self.base}/", timeout=5)
        allow = r.headers.get("Allow", "")
        for method in ("PUT", "DELETE", "TRACE", "PATCH"):
            self.assertIn(method, allow)

    # -------------------------------------------------------- sensitive paths
    def test_sensitive_paths_served(self):
        checks = {
            "/.env": b"DB_PASSWORD",
            "/.git/HEAD": b"ref: refs/heads/main",
            "/.git/config": b"github.com/acme",
            "/backup.zip": b"PK",                       # zip magic
            "/server-status": b"Apache Server Status",
            "/phpinfo.php": b"PHP Version",
            "/.aws/credentials": b"aws_access_key_id",
            "/config.php.bak": b"db_pass",
        }
        for path, marker in checks.items():
            r = requests.get(f"{self.base}{path}", timeout=5)
            self.assertEqual(r.status_code, 200, path)
            self.assertIn(marker, r.content, path)

    def test_robots_discloses_sensitive_paths(self):
        r = requests.get(f"{self.base}/robots.txt", timeout=5)
        self.assertIn("Disallow: /admin", r.text)
        self.assertIn("Disallow: /.env", r.text)

    # ------------------------------------------------------------ injection
    def test_reflected_xss_raw(self):
        r = requests.get(f"{self.base}/search",
                         params={"q": "<script>alert(1)</script>"},
                         timeout=5)
        self.assertIn("<script>alert(1)</script>", r.text)

    def test_sql_error_disclosure(self):
        r = requests.get(f"{self.base}/product", params={"id": "1'"},
                         timeout=5)
        self.assertIn("SQL syntax", r.text)
        self.assertIn("MySQL", r.text)

    def test_path_traversal_reads_vault(self):
        r = requests.get(f"{self.base}/download",
                         params={"file": "../secret_vault.txt"}, timeout=5)
        self.assertEqual(r.status_code, 200)
        self.assertIn(vulnserver.VAULT_MARKER, r.text)

    def test_traversal_extension_allowlist(self):
        r = requests.get(f"{self.base}/download",
                         params={"file": "../vulnserver.py"}, timeout=5)
        self.assertEqual(r.status_code, 403)

    # ------------------------------------------------------------ access flaws
    def test_open_redirect(self):
        r = requests.get(f"{self.base}/redirect",
                         params={"next": "http://evil.example/"},
                         allow_redirects=False, timeout=5)
        self.assertEqual(r.status_code, 302)
        self.assertEqual(r.headers.get("Location"), "http://evil.example/")

    def test_profile_idor_without_auth(self):
        r = requests.get(f"{self.base}/api/profile",
                         params={"id": "2"}, timeout=5)
        self.assertEqual(r.status_code, 200)
        self.assertIn("444-55-6666", r.text)   # planted PII, no auth check

    def test_admin_panel_unauthenticated(self):
        r = requests.get(f"{self.base}/admin", timeout=5)
        self.assertEqual(r.status_code, 200)
        self.assertIn("Admin Dashboard", r.text)

    def test_verbose_500_traceback(self):
        r = requests.get(f"{self.base}/crash", timeout=5)
        self.assertEqual(r.status_code, 500)
        self.assertIn("Traceback", r.text)
        self.assertIn("ValueError", r.text)

    def test_no_csrf_token_on_login_form(self):
        r = requests.get(f"{self.base}/login", timeout=5)
        self.assertNotIn("csrf", r.text.lower())

    # ------------------------------------------------------------------ auth
    def test_json_login_and_profile_flow(self):
        bad = requests.post(f"{self.base}/rest/user/login",
                            json={"email": "alice@example.com",
                                  "password": "wrong"}, timeout=5)
        self.assertEqual(bad.status_code, 401)
        ok = requests.post(f"{self.base}/rest/user/login",
                           json={"email": "alice@example.com",
                                 "password": "alicepw1"}, timeout=5)
        self.assertEqual(ok.status_code, 200)
        self.assertIn("lab.", ok.json().get("token", ""))

    def test_form_login_sets_cookie_and_verifies(self):
        s = requests.Session()
        s.post(f"{self.base}/login",
               data={"email": "bob@example.com", "password": "bobpw2"},
               allow_redirects=False, timeout=5)
        v = s.get(f"{self.base}/verify", timeout=5)
        self.assertIn("bob@example.com", v.text)

    # --------------------------------------------------------------- safety
    def test_refuses_non_loopback_bind(self):
        with self.assertRaises(SystemExit):
            vulnserver.main(["--host", "0.0.0.0", "--port", "0"])


if __name__ == "__main__":
    unittest.main()
