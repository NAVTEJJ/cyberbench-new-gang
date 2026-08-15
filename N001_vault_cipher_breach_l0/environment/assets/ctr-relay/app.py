from __future__ import annotations

import base64
import json
import os
import struct
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, os.path.dirname(__file__))
from aes_cbc import aes_cbc_encrypt, aes_cbc_decrypt_raw, pkcs7_unpad

FLAG = Path("/app/flag.txt").read_text().strip()
KEY = os.urandom(32)
IV = os.urandom(16)

ROLE_GUEST = 0x00
ROLE_ADMIN = 0x01


def pack_token(username: str) -> bytes:
    uname = username.encode("utf-8")
    ts = int(time.time())
    header = struct.pack(">BB", 0x01, len(uname))
    body = uname + struct.pack(">BI", ROLE_GUEST, ts)
    return header + body


def parse_token(data: bytes) -> dict | None:
    try:
        if len(data) < 6:
            return None
        version, ulen = struct.unpack_from(">BB", data, 0)
        if version != 0x01 or ulen != len(data) - 7:
            return None
        role, ts = struct.unpack_from(">BI", data, 2 + ulen)
        username = data[2:2 + ulen].decode("utf-8", errors="replace")
        return {"username": username, "role": role, "ts": ts}
    except Exception:
        return None


class Handler(BaseHTTPRequestHandler):
    def _send(self, code, payload):
        body = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _body(self):
        length = int(self.headers.get("Content-Length", 0))
        if not length:
            return {}
        raw = self.rfile.read(length)
        return json.loads(raw)

    def do_GET(self):
        if self.path == "/":
            self._send(200, {
                "service": "relay",
                "endpoints": ["/login", "/verify"],
            })
        else:
            self._send(404, {"error": "not found"})

    def do_POST(self):
        if self.path == "/login":
            body = self._body()
            username = body.get("username", "")
            if not username or len(username) > 100:
                self._send(400, {"error": "invalid username"})
                return
            token_data = pack_token(username)
            token_ct = aes_cbc_encrypt(KEY, IV, token_data)
            self._send(200, {"token": base64.b64encode(token_ct).decode()})

        elif self.path == "/verify":
            body = self._body()
            token_b64 = body.get("token")
            if token_b64 is None:
                self._send(400, {"error": "missing token"})
                return
            try:
                token_ct = base64.b64decode(token_b64, validate=True)
            except Exception:
                self._send(400, {"error": "token must be base64"})
                return
            if len(token_ct) < 32 or len(token_ct) % 16 != 0:
                self._send(400, {"error": "invalid token length"})
                return
            iv = token_ct[:16]
            payload = token_ct[16:]
            try:
                raw_pt = aes_cbc_decrypt_raw(KEY, iv, payload)
                pt = pkcs7_unpad(raw_pt)
            except Exception:
                self._send(400, {"error": "invalid token"})
                return
            parsed = parse_token(pt)
            if parsed is None:
                self._send(400, {"error": "invalid token data"})
                return
            if parsed["role"] == ROLE_ADMIN:
                self._send(200, {"role": "admin", "flag": FLAG})
            else:
                self._send(200, {"role": "guest", "flag": None})
        else:
            self._send(404, {"error": "not found"})

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    server = ThreadingHTTPServer(("0.0.0.0", 5000), Handler)
    server.serve_forever()