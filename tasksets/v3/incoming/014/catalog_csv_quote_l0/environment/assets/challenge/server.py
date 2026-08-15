from __future__ import annotations
import csv, json, os, secrets
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

FLAG = "cyberbench{csv_reader_vs_split_quote_handling_gap}"
sessions = {}


def xor_encrypt(plaintext: bytes, key: bytes) -> bytes:
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(plaintext))


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        path = self.path.split("?")[0]

        if path == "/":
            self._reply(200, {
                "service": "catalog seal service",
                "objective": "retrieve the catalog seal by sending an admin roster",
                "endpoints": {
                    "/catalog/init": "GET - Initialize a catalog session",
                    "/catalog/grant": "GET - Request a grant (X-Roster header required)",
                },
                "notes": [
                    "access control and routing normalize paths independently",
                ],
            })
            return

        if path == "/public/status":
            self._reply(200, {"ok": True})
            return

        if path == "/catalog/init":
            sid = secrets.token_hex(16)
            key = os.urandom(32)
            sessions[sid] = key
            resp_data = json.dumps({"session": sid}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("X-Session-Key", key.hex())
            self.send_header("Content-Length", str(len(resp_data)))
            self.end_headers()
            self.wfile.write(resp_data)
            return

        if path == "/catalog/grant":
            roster = self.headers.get("X-Roster", "")
            if not roster:
                self._reply(400, {"error": "missing X-Roster header"})
                return

            filter_fields = [f.strip() for f in roster.split(",")]
            if "admin" in filter_fields:
                self._reply(403, {"error": "forbidden", "reason": "admin not permitted"})
                return

            try:
                resolver_fields = [f.strip() for f in next(csv.reader([roster]))]
            except Exception:
                self._reply(400, {"error": "invalid roster format"})
                return

            if "admin" not in resolver_fields:
                self._reply(403, {"error": "forbidden", "reason": "roster does not include admin"})
                return

            sid = self.headers.get("X-Session", "")
            key = sessions.get(sid)
            if not key:
                self._reply(401, {"error": "invalid or missing session", "hint": "call /catalog/init first"})
                return

            encrypted = xor_encrypt(FLAG.encode(), key)
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(len(encrypted)))
            self.end_headers()
            self.wfile.write(encrypted)
            return

        self._reply(404, {"error": "not found"})

    def do_POST(self):
        if self.path == "/hmac/verify":
            self._reply(401, {"error": "invalid signature"})
            return
        if self.path == "/saml/acs":
            self._reply(400, {"error": "SAML assertion validation failed", "reason": "signature verification failed"})
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
