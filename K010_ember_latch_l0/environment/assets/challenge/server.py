from __future__ import annotations
import hashlib, json, os, struct, re, base64
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import unquote

FLAG = "cyberbench{triple_round_setdefault_isnumeric_composition}"
FAKE_FLAG = "cyberbench{decoy_saml_authenticated}"
sessions = {}

def xor_encrypt(plaintext: bytes, key: bytes) -> bytes:
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(plaintext))

class Handler(BaseHTTPRequestHandler):
    server_version = ""
    sys_version = ""

    def version_string(self):
        return ""

    def do_POST(self):
        path = self.path.split("?")[0]
        if path == "/api/session":
            sid = os.urandom(8).hex()
            sessions[sid] = {"fragments": []}
            self._reply(200, {"session": sid})
            return
        if path == "/saml/acs":
            body = json.dumps({"status": "authenticated", "grant": "see headers"}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("X-SAML-Grant", FAKE_FLAG)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if path == "/graphql":
            self._reply(200, {"data": {}})
            return
        sid = self.headers.get("X-Session", "")
        if sid not in sessions:
            self._reply(401, {"error": "invalid session"})
            return
        if path == "/api/level":
            length = int(self.headers.get("Content-Length", 0))
            try:
                data = json.loads(self.rfile.read(length))
            except Exception:
                self._reply(400, {"error": "invalid JSON"})
                return
            if not isinstance(data, dict) or "level" not in data:
                self._reply(400, {"error": "level required"})
                return
            level = data["level"]
            if not isinstance(level, (int, float)) or isinstance(level, bool):
                self._reply(400, {"error": "level must be numeric"})
                return
            if round(level) == 3:
                self._reply(403, {"error": "forbidden"})
                return
            if int(level) == 3:
                fragment = os.urandom(16).hex()
                sessions[sid]["fragments"].append(fragment)
                self._reply(200, {"fragment": fragment})
                return
            self._reply(404, {"error": "not found", "resolved": int(level)})
            return
        if path == "/api/user":
            length = int(self.headers.get("Content-Length", 0))
            try:
                data = json.loads(self.rfile.read(length))
            except Exception:
                self._reply(400, {"error": "invalid JSON"})
                return
            if not isinstance(data, dict) or "username" not in data:
                self._reply(400, {"error": "username required"})
                return
            username = data["username"]
            if not isinstance(username, str):
                self._reply(400, {"error": "username must be string"})
                return
            users = {"guest": 1, "user": 2}
            try:
                result = users[username]
                self._reply(403, {"error": "forbidden"})
                return
            except KeyError:
                pass
            if users.setdefault(username, "granted") == "granted":
                fragment = os.urandom(16).hex()
                sessions[sid]["fragments"].append(fragment)
                self._reply(200, {"fragment": fragment})
                return
            self._reply(404, {"error": "not found"})
            return

        self._reply(404, {"error": "not found"})

    def do_GET(self):
        path = self.path.split("?")[0]
        if path == "/":
            self._reply(200, {
                "service": "triple gate",
                "objective": "pass all three gates and access the admin vault",
                "endpoints": {
                    "/api/session": "POST - Create a session",
                    "/api/level": "POST - Set level (JSON: level)",
                    "/api/user": "POST - Submit username (JSON: username)",
                    "/api/token/<token>": "GET - Validate a numeric token",
                    "/api/admin": "GET - Access admin vault",
                },
                "notes": [
                    "access control and routing operate independently",
                    "authentication tokens are validated through standard protocols",
                ],
            })
            return
        if path == "/public/status":
            self._reply(200, {"ok": True})
            return


        if path.startswith("/api/token/"):
            sid = self.headers.get("X-Session", "")
            if sid not in sessions:
                self._reply(401, {"error": "invalid session"})
                return
            token = unquote(path[len("/api/token/"):])
            if token.isdigit():
                self._reply(403, {"error": "forbidden", "reason": "digit token blocked"})
                return
            if token.isnumeric():
                fragment = os.urandom(16).hex()
                sessions[sid]["fragments"].append(fragment)
                self._reply(200, {"fragment": fragment})
                return
            self._reply(404, {"error": "not found"})
            return
        if path == "/api/admin":
            sid = self.headers.get("X-Session", "")
            if sid not in sessions:
                self._reply(401, {"error": "invalid session"})
                return
            fragments = sessions[sid]["fragments"]
            if len(fragments) < 3:
                self._reply(403, {"error": "insufficient fragments", "collected": len(fragments), "required": 3})
                return
            combined = "".join(fragments[:3])
            key = hashlib.sha256(combined.encode()).digest()[:32]
            encrypted = xor_encrypt(FLAG.encode(), key)
            payload = b"\x7fENC" + encrypted
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
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
