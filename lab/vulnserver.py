"""Docker-free vulnerable lab server — the eval target (Step L).

A deliberately vulnerable, stdlib-only HTTP application for measuring the
pipeline's recall WITHOUT containers: planted issues across the catalog's
web sections (security headers, cookie flags, CORS, exposed sensitive
files, directory listing, dangerous methods, reflected XSS, SQL error
disclosure, path traversal, open redirect, unauthenticated admin/profile
access, verbose errors). Ground truth for scoring lives in
eval/targets.yaml under the target `lab`.

SAFETY:
  * binds 127.0.0.1 ONLY — refuses any non-loopback --host, so the planted
    weaknesses are never reachable from another machine;
  * plain HTTP, single process, no amplification or DoS behaviors
    (catalog section 22 stays excluded even here);
  * every weak spot exists to be DETECTED; nothing here executes anything
    against a third party.

Run:   python lab/vulnserver.py [--port 8000]
Stop:  Ctrl+C
"""

from __future__ import annotations

import argparse
import io
import json
import os
import traceback
import uuid
import zipfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse

LAB_DIR = Path(__file__).resolve().parent
DATA_DIR = LAB_DIR / "data"

# traversal target: readable ONLY through the planted ../ hole in /download
VAULT_MARKER = "LAB_SECRET_7f3a9c2e"

# planted accounts (weak on purpose) — used by /login form + JSON API
USERS = {
    "alice@example.com": "alicepw1",
    "bob@example.com": "bobpw2",
    "admin@lab.test": "adminpw123",
}
SESSIONS: dict[str, str] = {}  # sid -> email

PROFILES = {
    "1": {"id": 1, "name": "Alice Operator", "email": "alice@example.com",
          "role": "user", "ssn": "111-22-3333",
          "notes": "default shipping address on file"},
    "2": {"id": 2, "name": "Bob Analyst", "email": "bob@example.com",
          "role": "user", "ssn": "444-55-6666",
          "notes": "card ending 4242"},
    "3": {"id": 3, "name": "Lab Admin", "email": "admin@lab.test",
          "role": "admin", "ssn": "999-88-7777",
          "notes": "backup codes: 1122-3344-5566"},
}

# every path web_security_checks probes for, served with a 200 on purpose
def _backup_zip() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("dump.sql",
                    "CREATE TABLE users (id INT, email TEXT, pass_hash TEXT);\n"
                    "INSERT INTO users VALUES (1,'alice@example.com','$2y$10$lab');\n")
        zf.writestr("wp-config.php",
                    "<?php define('DB_PASSWORD', 'lab_backup_pw'); ?>\n")
    return buf.getvalue()


SENSITIVE: dict[str, tuple[str, bytes]] = {
    "/.git/HEAD": ("text/plain", b"ref: refs/heads/main\n"),
    "/.git/config": ("text/plain",
                     b"[core]\n\trepositoryformatversion = 0\n\tbare = false\n"
                     b"[remote \"origin\"]\n"
                     b"\turl = https://github.com/acme/lab-webapp.git\n"
                     b"\tfetch = +refs/heads/*:refs/remotes/origin/*\n"),
    "/.env": ("text/plain",
              b"APP_ENV=production\n"
              b"DB_PASSWORD=hunter2_lab_secret\n"
              b"AWS_SECRET_ACCESS_KEY=lab/fake+secret/key\n"
              b"SESSION_SECRET=super-secret-lab\n"
              b"SMTP_PASSWORD=hunter2_lab_secret\n"),
    "/.svn/entries": ("text/plain",
                      b"10\ndir\n1234\nhttps://svn.acme.local/lab/trunk\n"),
    "/.DS_Store": ("application/octet-stream", b"\x00\x00\x00\x01Bud1" * 4),
    "/.aws/credentials": ("text/plain",
                          b"[default]\naws_access_key_id = AKIALABFAKEKEY\n"
                          b"aws_secret_access_key = lab-secret-key\n"),
    "/server-status": ("text/html",
                       b"<html><head><title>Apache Server Status</title></head>"
                       b"<body><h1>Apache Server Status for 127.0.0.1</h1>"
                       b"<dl><dt>Server Version: Apache/2.4.49 (Unix)</dt>"
                       b"<dt>Current Time: now</dt></dl>"
                       b"<table><tr><th>Request</th></tr>"
                       b"<tr><td>GET /login HTTP/1.1</td></tr></table>"
                       b"</body></html>"),
    "/actuator/health": ("application/json",
                         b'{"status":"UP","components":{"db":{"status":"UP"},'
                         b'"diskSpace":{"status":"UP"}}}'),
    "/phpinfo.php": ("text/html",
                     b"<html><head><title>phpinfo()</title></head><body>"
                     b"<h1>PHP Version 7.4.3</h1>"
                     b"<div>Configuration File (php.ini) Path: /etc/php/7.4</div>"
                     b"</body></html>"),
    "/backup.zip": ("application/zip", _backup_zip()),
    "/config.php.bak": ("text/plain",
                        b"<?php\n$db_host = 'localhost';\n$db_user = 'root';\n"
                        b"$db_pass = 'lab_root_pw';\n?>\n"),
}


def _page(title: str, body: str) -> bytes:
    return (
        "<!doctype html><html><head>"
        f"<title>{title}</title>"
        '<meta charset="utf-8">'
        "</head><body>"
        # planted: no CSP/XFO/XCTO/Referrer-Policy/HSTS anywhere
        f"<h1>{title}</h1>{body}"
        "</body></html>"
    ).encode("utf-8")


def _qs(parsed) -> dict[str, str]:
    return {k: v[0] for k, v in parse_qs(parsed.query).items()}


class LabHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    # default server_version/sys_version kept: the Server header discloses
    # BaseHTTP + the real Python version on purpose (technology disclosure).

    # ---------------------------------------------------------------- plumbing
    def log_message(self, fmt, *args):  # quiet by default; --verbose sets it
        if getattr(self.server, "verbose", False):
            super().log_message(fmt, *args)

    def _send(self, code: int, body: bytes | str, ctype: str = "text/html; charset=utf-8",
              extra: list[tuple[str, str]] | None = None) -> None:
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        # planted: reflected Origin + credentials on EVERY response
        origin = self.headers.get("Origin")
        self.send_header("Access-Control-Allow-Origin",
                         origin if origin else "*")
        self.send_header("Access-Control-Allow-Credentials", "true")
        self.send_header("Access-Control-Allow-Methods",
                         "GET, POST, PUT, DELETE, OPTIONS, TRACE, PATCH")
        # planted: framework fingerprint
        self.send_header("X-Powered-By", "PHP/7.4.3")
        for key, value in (extra or []):
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def _redirect(self, location: str,
                  extra: list[tuple[str, str]] | None = None) -> None:
        # CRLF is sanitized (header injection would break the LAB itself);
        # the open redirect itself remains fully planted.
        location = location.replace("\r", "").replace("\n", "")
        self.send_response(302)
        self.send_header("Location", location)
        self.send_header("Content-Length", "0")
        self.send_header("Access-Control-Allow-Origin", "*")
        for key, value in (extra or []):
            self.send_header(key, value)
        self.end_headers()

    def _cookie_email(self) -> str | None:
        raw = self.headers.get("Cookie", "")
        for part in raw.split(";"):
            name, _, value = part.strip().partition("=")
            if name == "session":
                return SESSIONS.get(value)
        return None

    # ------------------------------------------------------------------ verbs
    def do_OPTIONS(self):
        self.send_response(200)
        # planted: unsafe methods advertised
        self.send_header("Allow", "GET, HEAD, POST, PUT, DELETE, OPTIONS, TRACE, PATCH")
        self.send_header("Access-Control-Allow-Origin",
                         self.headers.get("Origin") or "*")
        self.send_header("Access-Control-Allow-Credentials", "true")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_PUT(self):
        length = int(self.headers.get("Content-Length") or 0)
        if length:
            self.rfile.read(length)
        self._send(200, "stored (unsafe method accepted without CSRF or auth)",
                   "text/plain")

    def do_DELETE(self):
        self._send(200, "deleted (unsafe method accepted without auth)",
                   "text/plain")

    def do_TRACE(self):
        echo = (f"{self.requestline}\r\n"
                + "".join(f"{k}: {v}\r\n" for k, v in self.headers.items()))
        self._send(200, echo, "message/http")

    def do_POST(self):
        self._dispatch(self._handle_post)

    def do_GET(self):
        self._dispatch(self._handle_get)

    def _dispatch(self, handler):
        try:
            handler()
        except ValueError:            # /crash plants this on purpose
            self._send(500, traceback.format_exc(), "text/plain; charset=utf-8")
        except BrokenPipeError:
            pass
        except Exception:             # any other stumble = verbose 500 (planted)
            self._send(500, "Unhandled server error\n\n" + traceback.format_exc(),
                       "text/plain; charset=utf-8")

    # ------------------------------------------------------------------- GET
    def _handle_get(self):
        parsed = urlparse(self.path)
        path = parsed.path
        q = _qs(parsed)

        if path in SENSITIVE:
            ctype, body = SENSITIVE[path]
            self._send(200, body, ctype)
            return

        if path == "/":
            # planted directory listing (web_security_checks looks for
            # "index of /" in the first 4 KiB)
            entries = "".join(
                f'<li><a href="{p}">{p}</a></li>'
                for p in ["/login", "/admin", "/search", "/product",
                          "/api/profile", "/download", "/redirect",
                          "/robots.txt", "/dashboard"])
            self._send(200,
                       "<!doctype html><html><head><title>Index of /</title></head>"
                       f"<body><h1>Index of /</h1><ul>{entries}</ul></body></html>")
            return

        if path == "/robots.txt":
            self._send(200,
                       "User-agent: *\n"
                       "Disallow: /admin\n"
                       "Disallow: /.env\n"
                       "Disallow: /backup.zip\n"
                       "Disallow: /api/profile\n"
                       "Disallow: /internal/\n",
                       "text/plain")
            return

        if path in ("/login", "/index.html", "/dashboard"):
            body = ("<p>Welcome to the lab storefront.</p>"
                    '<form method="POST" action="/login">'
                    '<input name="email" placeholder="email">'
                    '<input name="password" type="password" placeholder="password">'
                    '<button type="submit">Sign in</button></form>'
                    # planted: form has NO CSRF token anywhere
                    "<p><a href='/admin'>Staff area</a></p>")
            extra = []
            if path == "/login":
                # planted: session cookie set on the login GET, no flags
                extra = [("Set-Cookie",
                          f"session={uuid.uuid4().hex}; Path=/")]
            self._send(200, _page("Lab storefront", body), extra=extra)
            return

        if path == "/verify":
            email = self._cookie_email()
            if email:
                self._send(200, f"logged in as {email}", "text/plain")
            else:
                self._send(401, "no session", "text/plain")
            return

        if path == "/admin":
            # planted: admin panel with zero authentication
            self._send(200, _page(
                "Admin Dashboard",
                "<p>No authentication required for this panel.</p>"
                "<table><tr><th>user</th><th>role</th></tr>"
                "<tr><td>alice@example.com</td><td>user</td></tr>"
                "<tr><td>admin@lab.test</td><td>admin</td></tr></table>"
                "<p>Deploy keys: LAB_ADMIN_KEY-9f8e7d6c</p>"))
            return

        if path == "/search":
            term = q.get("q", "")
            # planted: raw reflection (reflected XSS)
            self._send(200, _page(
                "Search",
                f"<p>You searched for: {term}</p>"
                f"<p>Results for '{term}' (0 hits)</p>"))
            return

        if path == "/product":
            pid = q.get("id", "1")
            if "'" in pid or "-" in pid or " OR " in pid.upper():
                # planted: SQL error disclosure
                self._send(200, _page(
                    "Product",
                    "<pre>error: You have an error in your SQL syntax; "
                    f"check the manual that corresponds to your MySQL server "
                    f"version for the right syntax to use near ''{pid}'' at "
                    "line 1\nquery: SELECT * FROM products WHERE id = "
                    f"'{pid}'</pre>"))
            else:
                self._send(200, _page("Product", f"<p>Product #{pid}</p>"))
            return

        if path == "/download":
            # planted: path traversal — naive join, no containment check.
            # Only a few extensions are served so the lab cannot cough up
            # binaries; the ../ hole itself is fully real.
            name = q.get("file", "")
            suffix = Path(name).suffix.lower()
            if suffix not in (".txt", ".log", ".json", ".md", ".csv", ".bak", ".sql"):
                self._send(403, "extension not allowed for download", "text/plain")
                return
            target = os.path.join(str(DATA_DIR), unquote(name))
            try:
                with open(target, "rb") as fh:
                    body = fh.read()
            except OSError as exc:
                self._send(404, f"cannot read {name}: {exc}", "text/plain")
                return
            self._send(200, body, "application/octet-stream")
            return

        if path == "/redirect":
            # planted: open redirect
            self._redirect(q.get("next", "http://evil.example/"))
            return

        if path == "/api/profile":
            # planted: predictable ids, NO auth check (IDOR + data leak)
            pid = q.get("id", "")
            if pid not in PROFILES:
                self._send(404, json.dumps({"error": "profile not found"}),
                           "application/json")
                return
            self._send(200, json.dumps(PROFILES[pid]), "application/json")
            return

        if path == "/crash":
            raise ValueError("deliberate lab crash: unhandled exception")  # planted: full traceback in 500

        if path == "/logout":
            self._redirect("/")
            return

        # planted: everything else 404s with an application fingerprint
        self._send(404, _page("Not found",
                              f"<p>No route for {path}</p>"
                              "<pre>werkzeug.exceptions.NotFound: "
                              f"no handler for {path}</pre>"))

    # ------------------------------------------------------------------ POST
    def _handle_post(self):
        parsed = urlparse(self.path)
        path = parsed.path
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b""

        if path == "/rest/user/login":  # JSON API login (identities kind: form)
            try:
                payload = json.loads(raw.decode("utf-8") or "{}")
            except json.JSONDecodeError:
                self._send(400, '{"error": "invalid json"}', "application/json")
                return
            email = str(payload.get("email", "") or payload.get("username", ""))
            password = str(payload.get("password", ""))
            if USERS.get(email) == password:
                sid = uuid.uuid4().hex
                SESSIONS[sid] = email
                # planted: session cookie without HttpOnly/SameSite/Secure
                self._send(200,
                           json.dumps({"status": "ok", "user": email,
                                       "token": f"lab.{sid}.unsigned"}),
                           "application/json",
                           extra=[("Set-Cookie",
                                   f"session={sid}; Path=/")])
            else:
                self._send(401, '{"error": "invalid credentials"}',
                           "application/json")
            return

        if path == "/login":  # HTML form login
            form = {k: v[0] for k, v in parse_qs(raw.decode("utf-8",
                                                            "replace")).items()}
            email = form.get("email", "")
            if USERS.get(email) == form.get("password", ""):
                sid = uuid.uuid4().hex
                SESSIONS[sid] = email
                # planted: session cookie without HttpOnly/SameSite/Secure
                # rides the redirect
                self._redirect("/dashboard",
                               extra=[("Set-Cookie",
                                       f"session={sid}; Path=/")])
                return
            self._send(200, _page("Login",
                                  "<p>Invalid credentials</p>"
                                  f"<p>debug: rejected {email}</p>"))
            return

        if path == "/logout":
            raw_cookie = self.headers.get("Cookie", "")
            for part in raw_cookie.split(";"):
                name, _, value = part.strip().partition("=")
                if name == "session":
                    SESSIONS.pop(value, None)
            self._redirect("/")
            return

        self._send(404, '{"error": "no route"}', "application/json")


def prepare_files() -> None:
    """Create DATA_DIR and the traversal vault. Used by main() AND by the
    smoke tests (which start the server in-process without main() — without
    this, a fresh checkout has no data/ dir and the traversal test would
    404 on case-sensitive filesystems)."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    vault = LAB_DIR / "secret_vault.txt"
    if not vault.exists():
        vault.write_text(f"{VAULT_MARKER}\n"
                         "tour-otp-backup: 555-0100\n", encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Vulnerable lab server (loopback only)")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args(argv)

    if args.host not in ("127.0.0.1", "localhost", "::1"):
        raise SystemExit("refusing to bind a non-loopback address: the planted "
                         "vulnerabilities must never be reachable off-host")

    prepare_files()

    server = ThreadingHTTPServer((args.host, args.port), LabHandler)
    server.verbose = args.verbose  # type: ignore[attr-defined]
    print(f"lab vulnserver listening on http://{args.host}:{args.port} "
          f"(loopback only — Ctrl+C to stop)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped")
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
