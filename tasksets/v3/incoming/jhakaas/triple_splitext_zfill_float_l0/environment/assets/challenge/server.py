from __future__ import annotations
import hashlib, json, os, struct, re, base64
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import unquote

FLAG = "cyberbench{triple_splitext_zfill_float_composition}"
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
        if path == "/oauth/authorize":
            body = json.dumps({"status": "authorized", "grant": "see headers"}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("X-OAuth-Grant", "cyberbench{decoy_oauth_authorized}")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if path == "/api/webauthn/register/begin":
            challenge = base64.urlsafe_b64encode(os.urandom(32)).decode()
            self._reply(200, {"challenge": challenge, "rp": {"id": "target"}})
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
        if path == "/api/upload":
            if not isinstance(data, dict) or "filename" not in data:
                self._reply(400, {"error": "filename required"})
                return
            filename = data["filename"]
            if not isinstance(filename, str):
                self._reply(400, {"error": "filename must be string"})
                return
            if filename == "admin":
                self._reply(403, {"error": "forbidden"})
                return
            ext = filename.rsplit('.', 1)[-1] if '.' in filename else ""
            if ext == "admin":
                fragment = os.urandom(16).hex()
                sessions[sid]["fragments"].append(fragment)
                self._reply(200, {"fragment": fragment})
                return
            self._reply(404, {"error": "extension not allowed", "ext": ext})
            return
        if path == "/api/code":
            if not isinstance(data, dict) or "code" not in data:
                self._reply(400, {"error": "code required"})
                return
            code = data["code"]
            if not isinstance(code, str):
                self._reply(400, {"error": "code must be string"})
                return
            if code.rjust(6, '0') == "-00500":
                self._reply(403, {"error": "forbidden"})
                return
            if code.zfill(6) == "-00500":
                fragment = os.urandom(16).hex()
                sessions[sid]["fragments"].append(fragment)
                self._reply(200, {"fragment": fragment})
                return
            self._reply(404, {"error": "not found"})
            return
        if path == "/api/configure":
            if not isinstance(data, dict) or "counter" not in data:
                self._reply(400, {"error": "counter required"})
                return
            counter = data["counter"]
            if not isinstance(counter, (int, float)) or isinstance(counter, bool):
                self._reply(400, {"error": "counter must be numeric"})
                return
            if counter is 0:
                self._reply(403, {"error": "forbidden"})
                return
            if counter == 0:
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
                    "/api/upload": "POST - Upload a file (JSON: filename)",
                    "/api/code": "POST - Submit a code (JSON: code)",
                    "/api/configure": "POST - Configure counter (JSON: counter)",
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
