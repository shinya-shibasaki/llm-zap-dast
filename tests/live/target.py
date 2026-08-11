"""Minimal token-auth target that mimics the Juice Shop shape.

- POST /rest/user/login        -> {"authentication":{"token":...}}  (200)
- GET  /rest/user/auth-details -> 200 {"lastLoginTime":...} with valid Bearer,
                                  401 {"status":"error"} without   (AUTH-ONLY endpoint)
- GET  /rest/products          -> 200 {"status":"success",...} with Bearer, 401 without
- GET  /rest/boom              -> 500 {"status":"error"}   (NON-auth error, always)
- GET  /                       -> 200 text/html  (no JSON wrapper at all)

Tokens expire after EXPIRE_AFTER seconds so session decay can be exercised.
"""
import json
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

EXPIRE_AFTER = float(sys.argv[2]) if len(sys.argv) > 2 else 1e9
TOKENS = {}
COUNTS = {"login": 0, "auth_details": 0, "products": 0, "boom": 0, "html": 0,
          "served_authed": 0, "served_401": 0}


class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def _send(self, code, body, ctype="application/json"):
        raw = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _valid(self):
        auth = self.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return None
        tok = auth[7:]
        issued = TOKENS.get(tok)
        if issued is None or (time.time() - issued) > EXPIRE_AFTER:
            return None
        return tok

    def do_POST(self):
        if self.path == "/rest/user/login":
            n = int(self.headers.get("Content-Length") or 0)
            self.rfile.read(n)
            COUNTS["login"] += 1
            tok = f"tok{COUNTS['login']}"
            TOKENS[tok] = time.time()
            self._send(200, json.dumps({"authentication": {"token": tok}}))
        else:
            self._send(404, json.dumps({"status": "error", "message": "no route"}))

    def do_GET(self):
        p = self.path.split("?")[0]
        if p == "/rest/user/auth-details":
            COUNTS["auth_details"] += 1
            if self._valid():
                self._send(200, json.dumps({"lastLoginTime": 1700000000, "user": "jim"}))
            else:
                COUNTS["served_401"] += 1
                self._send(401, json.dumps({"status": "error", "message": "unauthorized"}))
        elif p == "/rest/products":
            COUNTS["products"] += 1
            if self._valid():
                self._send(200, json.dumps({"status": "success", "data": ["a", "b"]}))
            else:
                COUNTS["served_401"] += 1
                self._send(401, json.dumps({"status": "error", "message": "unauthorized"}))
        elif p == "/rest/boom":
            COUNTS["boom"] += 1
            self._send(500, json.dumps({"status": "error", "message": "internal"}))
        elif p == "/__counts":
            self._send(200, json.dumps(COUNTS))
        elif p == "/__reset":
            for k in COUNTS:
                COUNTS[k] = 0
            TOKENS.clear()
            self._send(200, json.dumps({"reset": True}))
        else:
            COUNTS["html"] += 1
            self._send(200, "<html><body><h1>app</h1><a href='/rest/products'>p</a>"
                            "<a href='/rest/boom'>b</a><a href='/page2'>2</a></body></html>",
                       "text/html")


ThreadingHTTPServer(("127.0.0.1", int(sys.argv[1])), H).serve_forever()
