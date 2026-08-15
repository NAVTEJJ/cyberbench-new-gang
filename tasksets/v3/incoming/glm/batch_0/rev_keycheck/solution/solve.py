#!/usr/bin/env python3
import re
import subprocess
import sys

KEY = "CyB3rR3vR0ck5!"


def main() -> int:
    out = subprocess.run(
        ["/app/challenge/keycheck", KEY],
        capture_output=True,
        text=True,
        timeout=10,
    )
    print(out.stdout, flush=True)
    sys.stderr.write(out.stderr)
    m = re.search(r"[A-Za-z0-9_]+\{[^}]+\}", out.stdout)
    if not m:
        return 1
    print(m.group(0), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
