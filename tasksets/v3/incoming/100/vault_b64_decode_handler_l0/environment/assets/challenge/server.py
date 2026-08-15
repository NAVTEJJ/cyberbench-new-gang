from __future__ import annotations
import base64, json, os, struct, zlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

FLAG = "cyberbench{b64_header_decode_strict_vs_ignore}"
BLOCKED_KEY = "admin"

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        path = self.path.split("?")[0]

        if path == "/":
            self._reply(200, {
                "service": "vault service",
                "objective": "access the admin vault entry",
                "endpoints": {"/vault/<entry>": "GET - Access vault entry (X-Vault-Key header, base64-encoded)"},
                "notes": ["access control and routing operate independently"],
            })
            return

        if path == "/public/status":
            self._reply(200, {"ok": True})
            return

        if path.startswith("/vault/"):
            key_header = self.headers.get("X-Vault-Key", "")
            if not key_header:
                self._reply(401, {"error": "missing X-Vault-Key header"})
                return

            try:
                key_bytes = base64.b64decode(key_header)
            except Exception:
                self._reply(400, {"error": "invalid base64 encoding"})
                return

            try:
                filter_key = key_bytes.decode('utf-8')
            except UnicodeDecodeError:
                filter_key = None

            if filter_key is not None and filter_key == BLOCKED_KEY:
                self._reply(403, {"error": "forbidden"})
                return

            resolver_key = key_bytes.decode('utf-8', errors='ignore')

            if resolver_key == BLOCKED_KEY:
                flag_bytes = FLAG.encode("utf-8")
                crc = zlib.crc32(flag_bytes) & 0xFFFF
                header = b"\x7fVLT"
                payload = header + struct.pack(">H", crc) + struct.pack(">H", len(flag_bytes)) + flag_bytes
                self.send_response(200)
                self.send_header("Content-Type", "application/octet-stream")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
                return

            self._reply(404, {"error": "not found", "resolved_key": resolver_key})
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
