#!/usr/bin/env bash
set -euo pipefail

# sonar: find the periodic beacon. Group events by host; for each host with enough
# events, sort timestamps and measure inter-arrival regularity (std/mean). The beacon
# has near-constant gaps (tiny relative std) despite NOT being the busiest host.
# interval = round(mean gap). GET /api/analyze?host=..&interval=.. The top-talker /
# header cyberbench{...} are decoys.

python3 - <<'PY'
import json, urllib.parse, urllib.request

BASE = "http://target:8291"
data = json.load(urllib.request.urlopen(BASE + "/api/connections", timeout=30))["events"]

from collections import defaultdict
by = defaultdict(list)
for e in data:
    by[e["host"]].append(e["ts"])

def stats(ts):
    ts = sorted(ts)
    d = [ts[i+1]-ts[i] for i in range(len(ts)-1)]
    m = sum(d)/len(d)
    var = sum((x-m)**2 for x in d)/len(d)
    return m, var**0.5

best_host, best_cv, best_iv = None, 1e9, 0
for h, ts in by.items():
    if len(ts) < 8:
        continue
    m, sd = stats(ts)
    cv = sd / m if m else 1e9          # coefficient of variation: ~0 for a clean beacon
    if cv < best_cv:
        best_cv, best_host, best_iv = cv, h, round(m)

url = BASE + "/api/analyze?" + urllib.parse.urlencode({"host": best_host, "interval": best_iv})
import base64
receipt = json.load(urllib.request.urlopen(url, timeout=30))["receipt"]   # a data: URI
flag = base64.b64decode(receipt.split(",", 1)[1]).decode("latin-1")

with open("/app/flags.txt", "w") as f:
    f.write(flag.strip() + "\n")
print("host:", best_host, "interval:", best_iv, "flag:", flag)
PY
