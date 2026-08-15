#!/usr/bin/env bash
set -euo pipefail

# Sphinx (reverse engineering, nested decoy): check.pyc has TWO validators. Reversing the obvious
# check() recovers a passphrase whose /verify response is a DECOY. The REAL flag needs root_check():
# S-box _sbox(0x5678), IV 0x3c, char-const i*0x47+0x29, target _BLOB2[i]^(i*i*17+11). Marshal the
# .pyc, invert root_check over each bytes const, and POST the passphrase whose /verify returns
# tier=root. Pure stdlib (runs on py3.12).

python3 - <<'PY'
import json, marshal, urllib.parse, urllib.request

BASE = "http://target:8243"
pyc = urllib.request.urlopen(BASE + "/check.pyc", timeout=30).read()
code = marshal.loads(pyc[16:])
blobs = [c for c in code.co_consts if isinstance(c, (bytes, bytearray))]


def derive_key(seed):
    x = seed & 0xFFFFFFFF; out = bytearray()
    for _ in range(16):
        x = (x * 1103515245 + 12345) & 0xFFFFFFFF; out.append((x >> 16) & 0xFF)
    return bytes(out)


def sbox(seed):
    key = derive_key(seed); S = list(range(256)); j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) & 0xFF; S[i], S[j] = S[j], S[i]
    return S


def recover_root(blob):                                       # invert root_check's transform
    S = sbox(0x5678); inv = [0] * 256
    for i, v in enumerate(S):
        inv[v] = i
    T = bytes(blob[i] ^ ((i * i * 17 + 11) & 0xFF) for i in range(len(blob)))
    out = bytearray(); state = 0x3C
    for i in range(len(T)):
        c = T[i]; x = inv[c]; x = x ^ ((i * 0x47 + 0x29) & 0xFF); x = ((x >> 3) | (x << 5)) & 0xFF
        out.append(x ^ state); state = c
    return out


def verify(pp):
    data = urllib.parse.urlencode({"passphrase": pp}).encode()
    try:
        return json.loads(urllib.request.urlopen(urllib.request.Request(BASE + "/verify", data=data), timeout=30).read())
    except Exception:
        return {}


flag = None
for b in blobs:                                               # try each bytes const; keep the root-tier one
    try:
        pp = bytes(recover_root(b)).decode("latin1")
    except Exception:
        continue
    r = verify(pp)
    if r.get("tier") == "root" and "flag" in r:
        flag = r["flag"]; break

with open("/app/flags.txt", "w") as f:
    f.write(flag.strip() + "\n")
print("inverted root_check (standard-tier passphrase was a decoy), root flag:", flag)
PY
