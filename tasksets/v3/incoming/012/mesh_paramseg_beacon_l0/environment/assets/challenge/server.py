from __future__ import annotations
import json, os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, urlsplit

FLAG = "cyberbench{urlparse_urlsplit_params_segment_gap}"
RESTRICTED_ROUTE = "/admin/staff/beacon-07"
CIPHER_KEY = os.urandom(32)

def xor_encrypt(plaintext: bytes, key: bytes) -> bytes:
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(plaintext))

class Handler(BaseHTTPRequestHandler):
    def send_response(self, code, message=None):
        self.send_response_only(code, message)
        self.send_header('Date', self.date_time_string())

    def do_GET(self):
        filter_path = urlsplit(self.path).path
        if filter_path == RESTRICTED_ROUTE:
            self._reply(403, {"error": "forbidden"})
            return

        resolve_path = urlparse(self.path).path

        if self.path == "/":
            self._reply(200, {
                "service": "mesh beacon service",
                "layout": "/<registry>/<tier>/<id>",
                "objective": "retrieve the beacon at /admin/staff/beacon-07",
            })
            return

        if self.path == "/public/status":
            self._reply(200, {"ok": True})
            return

        if resolve_path == RESTRICTED_ROUTE:
            encrypted = xor_encrypt(FLAG.encode(), CIPHER_KEY)
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("X-Cipher-Key", CIPHER_KEY.hex())
            self.send_header("Content-Length", str(len(encrypted)))
            self.end_headers()
            self.wfile.write(encrypted)
            return

        self._reply(404, {"error": "not found"})

    def do_POST(self):
        if self.path == "/saml/acs":
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length).decode("utf-8", errors="replace")
            if "SAMLResponse" not in body:
                self._reply(400, {"error": "missing SAMLResponse"})
                return
            self._reply(400, {"error": "SAML assertion validation failed",
                              "reason": "signature verification failed"})
            return
        if self.path == "/api/token":
            self._reply(401, {"error": "invalid credentials"})
            return
        if self.path == "/spiffe/verify":
            svid = self.headers.get("X-SPIFFE-SVID", "")
            if not svid:
                self._reply(401, {"status": "verification_required",
                                  "message": "Provide a valid SPIFFE SVID"})
                return
            self._reply(403, {"status": "verification_failed",
                              "reason": "SVID signature verification not supported"})
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