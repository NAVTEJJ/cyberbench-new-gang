#!/usr/bin/env bash
set -euo pipefail

# ariadne: submit the MIN-CUT edge set (not the flow value). Run Edmonds-Karp; the
# residual-reachable set from S defines the cut: original edges u->v with u reachable,
# v not. Submit them. "Cut the source edges" fails (internal bottleneck); the flow
# NUMBER is a decoy.

python3 - <<'PY'
import json, urllib.parse, urllib.request
from collections import defaultdict, deque

BASE = "http://target:8292"
g = json.load(urllib.request.urlopen(BASE + "/api/network", timeout=30))
edges = [(e["from"], e["to"], e["capacity"]) for e in g["edges"]]
S, T = g["source"], g["sink"]

cap = defaultdict(int); adj = defaultdict(set)
for u, v, c in edges:
    cap[(u, v)] += c; adj[u].add(v); adj[v].add(u)

while True:
    parent = {S: None}; q = deque([S])
    while q:
        u = q.popleft()
        if u == T: break
        for v in adj[u]:
            if v not in parent and cap[(u, v)] > 0:
                parent[v] = u; q.append(v)
    if T not in parent: break
    b = 1 << 60; v = T
    while parent[v] is not None:
        b = min(b, cap[(parent[v], v)]); v = parent[v]
    v = T
    while parent[v] is not None:
        u = parent[v]; cap[(u, v)] -= b; cap[(v, u)] += b; v = u

reach = set(); q = deque([S])
while q:
    u = q.popleft()
    if u in reach: continue
    reach.add(u)
    for v in adj[u]:
        if cap[(u, v)] > 0 and v not in reach:
            q.append(v)

cut = [[u, v] for u, v, c in edges if u in reach and v not in reach]
url = BASE + "/api/submit?" + urllib.parse.urlencode({"edges": json.dumps(cut)})
resp = urllib.request.urlopen(url, timeout=30)
# grant is issued as a Set-Cookie, not in the JSON body
import re
flag = re.search(r"grant=([^;]+)", resp.headers.get("Set-Cookie", "")).group(1)

with open("/app/flags.txt", "w") as f:
    f.write(flag.strip() + "\n")
print("cut:", cut, "flag:", flag)
PY
