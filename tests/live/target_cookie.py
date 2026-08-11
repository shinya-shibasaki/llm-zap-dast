"""Minimal cookie-session target shaped like Rails/Django/Laravel.

The other target (target.py) is token/JSON shaped like Juice Shop. This one exists because
the two fail differently: a session app answers an unauthenticated request with a REDIRECT
to the login page rather than a 401 with a body, and its "logged in" evidence often lives in
a response HEADER (Set-Cookie / X-Authenticated-User) rather than in the body.

- GET  /login       -> 200 HTML login form (always)
- POST /login       -> 302 Location: /account, Set-Cookie: sessionid=... (good credentials)
                       200 HTML "Invalid credentials" (bad ones)
- GET  /account     -> session: 200 HTML "Signed in as <user> ... Sign out"
                       none:    302 Location: /login  with an EMPTY body
- GET  /profile     -> session: 301 Location: /profile/   (trailing-slash redirect)
                       none:    302 Location: /login
- GET  /profile/    -> session: 200 HTML with the identity; none: 302 /login
- GET  /app         -> SPA shell: byte-identical body either way. Authenticated responses
                       carry `X-Authenticated-User: <user>`; anonymous ones carry a
                       `Set-Cookie` for a fresh empty session. Body-only matching is blind
                       to both.
- GET  /api/me      -> 200 {"user":"<user>"} / 401 {"error":"unauthenticated"}
- GET  /guarded     -> session: 200 JSON with the identity
                       none:    the connection is CLOSED with no response at all — what a
                       reverse proxy or WAF in front of a session app does to a client it
                       will not talk to. The authenticated read succeeds and the
                       unauthenticated read fails, which is the shape that turns a missing
                       unauth response into a false "differential" pass.
- GET  /expired     -> 302 Location: /logout?next=/login  ("your session has expired")
- GET  /logout      -> destroys the session, 302 to /login. Following a redirect here ends
                       the session the probe is verifying — the reason the redirect walk
                       refuses session-ending targets whether or not they are in
                       `exclude.paths`.
- GET  /boom        -> 500 (a NON-auth error, always)
- GET  /__counts, /__reset

Sessions expire after EXPIRE_AFTER seconds (argv[2]) so decay can be exercised.
Accounts: alice/pw-alice and bob/pw-bob, for mutual-identity differential checks.
"""
import json
import sys
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs

EXPIRE_AFTER = float(sys.argv[2]) if len(sys.argv) > 2 else 1e9
ACCOUNTS = {"alice@test.local": ("pw-alice", "alice"),
            "bob@test.local": ("pw-bob", "bob")}
SESSIONS = {}  # sid -> (user, issued_at)
COUNTS = {"login_get": 0, "login_post": 0, "login_ok": 0, "account": 0, "profile": 0,
          "app": 0, "api_me": 0, "guarded": 0, "expired": 0, "logout": 0, "boom": 0,
          "served_authed": 0, "served_anon": 0}

SHELL = ("<!doctype html><html><head><title>app</title></head>"
         "<body><div id='root'></div><script src='/static/app.js'></script></body></html>")


class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def _send(self, code, body, ctype="text/html", extra=()):
        raw = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(raw)))
        for k, v in extra:
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(raw)

    def _redirect(self, code, location, extra=()):
        self.send_response(code)
        self.send_header("Location", location)
        self.send_header("Content-Length", "0")
        for k, v in extra:
            self.send_header(k, v)
        self.end_headers()

    def _user(self):
        """The signed-in user for this request's cookie, or None."""
        raw = self.headers.get("Cookie", "")
        for part in raw.split(";"):
            name, _, value = part.strip().partition("=")
            if name == "sessionid" and value in SESSIONS:
                user, issued = SESSIONS[value]
                if (time.time() - issued) <= EXPIRE_AFTER:
                    return user
        return None

    # --- routes --------------------------------------------------------------
    def do_POST(self):
        if self.path.split("?")[0] != "/login":
            self._send(404, "<html>no route</html>")
            return
        COUNTS["login_post"] += 1
        n = int(self.headers.get("Content-Length") or 0)
        form = parse_qs(self.rfile.read(n).decode("utf-8", "replace"))
        email = (form.get("username") or [""])[0]
        password = (form.get("password") or [""])[0]
        known = ACCOUNTS.get(email)
        if known and known[0] == password:
            COUNTS["login_ok"] += 1
            sid = uuid.uuid4().hex
            SESSIONS[sid] = (known[1], time.time())
            self._redirect(302, "/account",
                           extra=[("Set-Cookie", f"sessionid={sid}; Path=/; HttpOnly")])
        else:
            self._send(200, "<html><body><h1>Sign in</h1>"
                            "<p>Invalid credentials</p></body></html>")

    def do_GET(self):
        p = self.path.split("?")[0]
        user = self._user()
        COUNTS["served_authed" if user else "served_anon"] += 1

        if p == "/login":
            COUNTS["login_get"] += 1
            self._send(200, "<html><body><h1>Sign in</h1><form method='post' action='/login'>"
                            "<input name='username'><input name='password' type='password'>"
                            "</form></body></html>")
        elif p == "/account":
            COUNTS["account"] += 1
            if user:
                self._send(200, f"<html><body><h1>Account</h1><p>Signed in as {user}</p>"
                                f"<a href='/logout'>Sign out</a></body></html>",
                           extra=[("X-Authenticated-User", user)])
            else:
                self._redirect(302, "/login")
        elif p == "/profile":
            COUNTS["profile"] += 1
            # Authenticated: a trailing-slash redirect. Anonymous: the login redirect.
            # Both are 3xx, so a client that follows one side only compares two different
            # things.
            self._redirect(301, "/profile/") if user else self._redirect(302, "/login")
        elif p == "/profile/":
            if user:
                self._send(200, f"<html><body><h1>Profile</h1><p>{user}@test.local</p>"
                                f"<a href='/logout'>Sign out</a></body></html>",
                           extra=[("X-Authenticated-User", user)])
            else:
                self._redirect(302, "/login")
        elif p == "/app":
            COUNTS["app"] += 1
            # Identical body both ways; the only difference is in the headers.
            if user:
                self._send(200, SHELL, extra=[("X-Authenticated-User", user)])
            else:
                self._send(200, SHELL, extra=[
                    ("Set-Cookie", f"sessionid={uuid.uuid4().hex}; Path=/; HttpOnly")])
        elif p == "/api/me":
            COUNTS["api_me"] += 1
            if user:
                self._send(200, json.dumps({"user": user, "email": f"{user}@test.local"}),
                           "application/json", extra=[("X-Authenticated-User", user)])
            else:
                self._send(401, json.dumps({"error": "unauthenticated"}), "application/json")
        elif p == "/expired":
            # "Your session has expired" — a redirect INTO logout, which is how a session
            # app destroys the session a verification probe is trying to confirm.
            COUNTS["expired"] += 1
            self._redirect(302, "/logout?next=/login")
        elif p == "/logout":
            COUNTS["logout"] += 1
            SESSIONS.clear()
            self._redirect(302, "/login",
                           extra=[("Set-Cookie", "sessionid=; Path=/; Max-Age=0")])
        elif p == "/guarded":
            COUNTS["guarded"] += 1
            if user:
                self._send(200, json.dumps({"user": user, "guarded": True}),
                           "application/json", extra=[("X-Authenticated-User", user)])
            else:
                # No response line at all: the peer just goes away.
                self.close_connection = True
                try:
                    self.connection.close()
                except OSError:
                    pass
        elif p == "/boom":
            COUNTS["boom"] += 1
            self._send(500, json.dumps({"error": "internal"}), "application/json")
        elif p == "/__counts":
            self._send(200, json.dumps(COUNTS), "application/json")
        elif p == "/__reset":
            for k in COUNTS:
                COUNTS[k] = 0
            SESSIONS.clear()
            self._send(200, json.dumps({"reset": True}), "application/json")
        else:
            self._send(200, SHELL)


ThreadingHTTPServer(("127.0.0.1", int(sys.argv[1])), H).serve_forever()
