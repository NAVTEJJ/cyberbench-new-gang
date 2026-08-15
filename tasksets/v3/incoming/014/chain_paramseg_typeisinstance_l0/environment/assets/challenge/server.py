from __future__ import annotations
import json, os, struct
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, urlsplit

FLAG = "cyberbench{chain_urlparse_type_isinstance_gap}"
RESTRICTED_ROUTE = "/admin/staff/gate-07"
CIPHER_KEY = os.urandom(32)

def xor_encrypt(plaintext: bytes, key: bytes) -> bytes:
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(plaintext))

class Handler(BaseHTTPRequestHandler):
    def send_response(self, code, message=None):
        self.send_response_only(code, message)
        self.send_header('Date', self.date_time_string())

    def do_GET(self):
        path = self.path.split("?")[0]

        if path == "/":
            self._reply(200, {
                "service": "gate keeper",
                "objective": "access the gate at /admin/staff/gate-07",
            })
            return

        if path == "/public/status":
            self._reply(200, {"ok": True})
            return

        filter_path = urlsplit(self.path).path
        if filter_path == RESTRICTED_ROUTE:
            self._reply(403, {"error": "forbidden"})
            return

        resolve_path = urlparse(self.path).path
        if resolve_path == RESTRICTED_ROUTE:
            self._reply(200, {"status": "gate accessed", "next": "/api/verify"})
            return

        self._reply(404, {"error": "not found"})

    def do_POST(self):
        path = self.path.split("?")[0]
        if path != "/api/verify":
            self._reply(404, {"error": "not found"})
            return

        length = int(self.headers.get("Content-Length", 0))
        try:
            data = json.loads(self.rfile.read(length))
        except Exception:
            self._reply(400, {"error": "invalid JSON"})
            return

        if not isinstance(data, dict) or "level" not in data:
            self._reply(400, {"error": "level required"})
            return
        if "role" not in data:
            self._reply(400, {"error": "role required"})
            return

        level = data["level"]
        role = data["role"]

        if role != "admin":
            self._reply(403, {"error": "insufficient role"})
            return

        if type(level) is int and level == 0:
            self._reply(403, {"error": "forbidden", "reason": "level 0 blocked"})
            return

        if isinstance(level, int) and level == 0:
            encrypted = xor_encrypt(FLAG.encode(), CIPHER_KEY)
            payload = b"\x7fGATE" + struct.pack("B", len(CIPHER_KEY)) + CIPHER_KEY + encrypted
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return

        if isinstance(level, int):
            self._reply(403, {"error": "insufficient clearance"})
            return

        self._reply(400, {"error": "level must be numeric"})

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
