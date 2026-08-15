from __future__ import annotations
import json, os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

FLAG = "cyberbench{cookie_json_bool_truthiness_identity_gap}"
HALF = len(FLAG) // 2

def parse_cookies(cookie_header: str) -> dict:
    cookies = {}
    if not cookie_header:
        return cookies
    for pair in cookie_header.split(";"):
        pair = pair.strip()
        if "=" in pair:
            k, v = pair.split("=", 1)
            cookies[k.strip()] = v.strip()
    return cookies

class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        path = self.path.split("?")[0]

        if path == "/api/login":
            length = int(self.headers.get("Content-Length", 0))
            try:
                data = json.loads(self.rfile.read(length))
            except Exception:
                self._reply(400, {"error": "invalid JSON"})
                return

            if data.get("username") == "guest" and data.get("password") == "guest":
                body = json.dumps({"status": "logged_in", "role": "user"}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Set-Cookie", "authorized=true")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return

            self._reply(401, {"error": "invalid credentials"})
            return

        self._reply(404, {"error": "not found"})

    def do_GET(self):
        path = self.path.split("?")[0]

        if path == "/":
            self._reply(200, {
                "service": "guardian api",
                "objective": "obtain admin grant authorization",
                "endpoints": {
                    "/api/login": "POST - Login (guest/guest)",
                    "/api/admin": "GET - Admin panel (requires authorization cookie)",
                },
                "notes": ["access control and routing operate independently"],
            })
            return

        if path == "/public/status":
            self._reply(200, {"ok": True})
            return

        if path == "/api/admin":
            cookies = parse_cookies(self.headers.get("Cookie", ""))
            auth_raw = cookies.get("authorized", "")

            if not auth_raw:
                self._reply(401, {"error": "missing authorization cookie"})
                return

            try:
                auth = json.loads(auth_raw)
            except (json.JSONDecodeError, ValueError):
                self._reply(400, {"error": "invalid cookie format"})
                return

            # Filter: strict identity — only Python True object is blocked
            if auth is True:
                self._reply(403, {"error": "forbidden", "reason": "admin access blocked"})
                return

            # Resolver: truthiness — any truthy value grants
            if bool(auth):
                body = json.dumps({"status": "granted"}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("X-Grant-Part1", FLAG[:HALF])
                self.send_header("X-Grant-Part2", FLAG[HALF:])
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return

            self._reply(403, {"error": "not authorized"})
            return

        self._reply(404, {"error": "not found"})

    def _reply(self, status, body):
        data = json.dumps(body, sort_keys=True).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args):
        return

ThreadingHTTPServer(("0.0.0.0", int(os.environ.get("PORT", "8297"))), Handler).serve_forever()
