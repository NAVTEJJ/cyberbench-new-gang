from __future__ import annotations
import base64, hashlib, json, os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import unquote

FLAG = "cyberbench{triple_isnumeric_ascii_zfill_composition}"
FAKE_FLAG_1 = "cyberbench{decoy_hmac_verified}"
FAKE_FLAG_2 = "cyberbench{decoy_saml_authenticated}"
sessions = {}
CODE_TARGET = "-00500"

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

        if path == "/hmac/verify":
            body = json.dumps({"status": "verified", "grant": "see headers"}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("X-HMAC-Grant", FAKE_FLAG_1)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        if path == "/saml/acs":
            body = json.dumps({"status": "authenticated", "grant": "see headers"}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("X-SAML-Grant", FAKE_FLAG_2)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        sid = self.headers.get("X-Session", "")
        if sid not in sessions:
            self._reply(401, {"error": "invalid session"})
            return

        length = int(self.headers.get("Content-Length", 0))
        try:
            data = json.loads(self.rfile.read(length))
        except Exception:
            self._reply(400, {"error": "invalid JSON"})
            return

        if path == "/api/code":
            if not isinstance(data, dict) or "code" not in data:
                self._reply(400, {"error": "code required"})
                return
            code = data["code"]
            if not isinstance(code, str):
                self._reply(400, {"error": "code must be string"})
                return
            if code.rjust(6, '0') == CODE_TARGET:
                self._reply(403, {"error": "forbidden"})
                return
            if code.zfill(6) == CODE_TARGET:
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
                    "/api/token/<token>": "GET - Validate a numeric token",
                    "/api/seal": "GET - Submit a seal key (X-Seal-Key, base64)",
                    "/api/code": "POST - Submit a code (JSON: code)",
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
            self._reply(404, {"error": "not a numeric token", "isdigit": token.isdigit(), "isnumeric": token.isnumeric()})
            return

        if path == "/api/seal":
            sid = self.headers.get("X-Session", "")
            if sid not in sessions:
                self._reply(401, {"error": "invalid session"})
                return
            key_header = self.headers.get("X-Seal-Key", "")
            if not key_header:
                self._reply(400, {"error": "missing X-Seal-Key header"})
                return
            try:
                key_bytes = base64.b64decode(key_header)
            except Exception:
                self._reply(400, {"error": "invalid base64 encoding"})
                return
            try:
                filter_key = key_bytes.decode('ascii')
            except UnicodeDecodeError:
                filter_key = None
            if filter_key is not None and "seal" in filter_key:
                self._reply(403, {"error": "forbidden"})
                return
            resolver_key = key_bytes.decode('utf-8')
            if "seal" in resolver_key:
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
