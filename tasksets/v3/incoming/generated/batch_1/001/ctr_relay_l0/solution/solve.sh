#!/usr/bin/env bash
set -euo pipefail

python3 - <<'PY'
import base64
import json
import struct
import urllib.request
import urllib.error

BASE = "http://target:8144"


def request_json(method, path, payload=None):
    data = json.dumps(payload or {}).encode() if payload is not None else None
    req = urllib.request.Request(
        BASE + path,
        data=data,
        headers={"Content-Type": "application/json"} if data is not None else {},
        method=method,
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


# Token format: version(1) | ulen(1) | username(N) | role(4 bytes, big-endian) | ts(4 bytes, big-endian)
# role is at offset 2+N, 4 bytes. role=0x00000000 for guest, 0x00000001 for admin.
# We need role to align at a block boundary. role starts at byte 2+N.
# For role to start at byte 32 (block 2): 2+N = 32 => N = 30.
# But role is 4 bytes (struct ">I"), so we flip byte 2+N+3 (the LSB) from 0x00 to 0x01.

username = "a" * 30
status, resp = request_json("POST", "/login", {"username": username})
token = bytearray(base64.b64decode(resp["token"]))

# Token format: version(1) | ulen(1) | username(N) | role(1 byte) | ts(4 bytes)
# role=0x00 for guest, 0x01 for admin. role is at plaintext byte 2+N.
# With N=30, role is at byte 32 = start of block 2.
# To flip plaintext byte 32 (block 2 byte 0), modify CT block 1 byte 0 = token[32].
# XOR with 0x01 to flip role from 0x00 to 0x01.

token[32] ^= 0x01

status, resp = request_json("POST", "/verify", {"token": base64.b64encode(token).decode()})
if resp.get("flag"):
    flag = resp["flag"]
    import pathlib
    pathlib.Path("/app/flags.txt").write_text(flag + "\n")
    print(flag)
else:
    raise SystemExit(f"forge failed: {resp}")
PY