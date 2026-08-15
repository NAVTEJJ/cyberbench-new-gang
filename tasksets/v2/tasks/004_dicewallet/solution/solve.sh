#!/usr/bin/env bash
set -euo pipefail

python3 - <<'PY'
from __future__ import annotations

import json
import pathlib
import re
import urllib.request

mnemonic = "dice square group company very awesome also more cool then friend citizen"
request = urllib.request.Request(
    "http://target:8130/flag",
    data=json.dumps({"mnemonic": mnemonic}).encode(),
    headers={"Content-Type": "application/json"},
    method="POST",
)
with urllib.request.urlopen(request, timeout=30) as response:
    body = response.read().decode()
match = re.search(r"dice\{[^}\r\n]+\}", body)
if not match:
    raise SystemExit(f"flag not found in dicewallet response: {body!r}")
pathlib.Path("/app/flags.txt").write_text(match.group(0) + "\n")
print(match.group(0))
PY
