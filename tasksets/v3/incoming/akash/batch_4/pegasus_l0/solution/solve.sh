#!/usr/bin/env bash
set -euo pipefail

# pegasus: ECDSA with a RELATED nonce (monotonic counter, k2 = k1 + 1), so r1 != r2 --
# "look for a repeated r" fails. Use the linear relation:
#   d = (s1*z2 - s2*z1 - s1*s2) / (s2*r1 - s1*r2)  (mod n).
# Recover d, sign the release command, POST (r,s) to /api/release.

python3 - <<'PY'
import hashlib, json, urllib.parse, urllib.request

BASE = "http://target:8262"
P  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
G  = (GX, GY)

def inv(a, m): return pow(a % m, m - 2, m)
def add(pt, qt):
    if pt is None: return qt
    if qt is None: return pt
    x1, y1 = pt; x2, y2 = qt
    if x1 == x2 and (y1 + y2) % P == 0: return None
    l = ((3*x1*x1)*inv(2*y1, P) if pt == qt else (y2-y1)*inv(x2-x1, P)) % P
    x3 = (l*l - x1 - x2) % P
    return (x3, (l*(x1-x3) - y1) % P)
def mul(k, pt):
    r = None; k %= N
    while k:
        if k & 1: r = add(r, pt)
        pt = add(pt, pt); k >>= 1
    return r
def h(msg): return int.from_bytes(hashlib.sha256(msg).digest(), "big") % N

adv = json.load(urllib.request.urlopen(BASE + "/api/advisories", timeout=30))
a, b = adv["advisories"]
m1 = a["msg"].encode(); r1, s1 = int(a["r"]), int(a["s"])
m2 = b["msg"].encode(); r2, s2 = int(b["r"]), int(b["s"])
delta = b["seq"] - a["seq"]                       # nonce counter step (= 1)
cmd = adv["release_command"].encode()
z1, z2 = h(m1), h(m2)

# related-nonce recovery (k2 = k1 + delta)
num = (s1 * z2 - s2 * z1 - delta * s1 * s2) % N
den = (s2 * r1 - s1 * r2) % N
d = num * inv(den, N) % N

# sign the release command with a fresh nonce
kf = (int.from_bytes(hashlib.sha256(cmd + b"|forge").digest(), "big") % (N - 1)) + 1
rf = mul(kf, G)[0] % N
sf = inv(kf, N) * (h(cmd) + rf * d) % N

data = urllib.parse.urlencode({"r": str(rf), "s": str(sf)}).encode()
resp = urllib.request.urlopen(urllib.request.Request(BASE + "/api/release", data=data, method="POST"), timeout=30)
# grant is delivered as multipart/mixed -- read the LAST part
body = resp.read()
flag = body.split(b"\r\n\r\n")[-1].split(b"\r\n--")[0].decode("latin-1").strip()

with open("/app/flags.txt", "w") as f:
    f.write(flag.strip() + "\n")
print("flag:", flag)
PY
