#!/usr/bin/env bash
set -euo pipefail

# hydra: AES-GCM nonce reuse (the "forbidden attack"). Two equal-length single-block
# envelopes share one nonce, so their length block L and keystream term S cancel:
#   T1 ^ T2 = (C1 ^ C2) * H^2  in GF(2^128)  ->  H = sqrt((T1^T2) * inv(C1^C2)).
# Then S = T1 ^ GHASH_H(C1) and keystream = C1 ^ P1 (P1 is published). We forge a
# valid (C*, T*) for the 16-byte command plaintext and POST it -- no key required.

python3 - <<'PY'
import json, urllib.parse, urllib.request

BASE = "http://target:8260"
COMMAND = b"UNSEAL ROOT VLT!"          # required 16-byte privileged plaintext
L = (0).to_bytes(8, "big") + (128).to_bytes(8, "big")

def gf_mult(x_b, y_b):
    R = 0xE1 << 120
    x = int.from_bytes(x_b, "big"); y = int.from_bytes(y_b, "big"); z = 0
    for i in range(128):
        if (x >> (127 - i)) & 1: z ^= y
        y = (y >> 1) ^ R if (y & 1) else (y >> 1)
    return z.to_bytes(16, "big")

def xor(a, b): return bytes(i ^ j for i, j in zip(a, b))

def gf_pow(a, e):
    r = (1 << 127).to_bytes(16, "big")   # multiplicative identity in GHASH rep
    base = a
    while e:
        if e & 1: r = gf_mult(r, base)
        base = gf_mult(base, base); e >>= 1
    return r

gf_inv  = lambda a: gf_pow(a, (1 << 128) - 2)
gf_sqrt = lambda a: gf_pow(a, 1 << 127)
ghash1  = lambda c, H: gf_mult(xor(gf_mult(c, H), L), H)

s = json.load(urllib.request.urlopen(BASE + "/api/samples", timeout=30))["samples"]
P1 = s[0]["plaintext"].encode(); C1 = bytes.fromhex(s[0]["ct"]); T1 = bytes.fromhex(s[0]["tag"])
C2 = bytes.fromhex(s[1]["ct"]); T2 = bytes.fromhex(s[1]["tag"])

H  = gf_sqrt(gf_mult(xor(T1, T2), gf_inv(xor(C1, C2))))   # recover GHASH subkey
S  = xor(T1, ghash1(C1, H))                               # recover keystream term
KS = xor(C1, P1)                                          # first-block keystream

Cstar = xor(COMMAND, KS)
Tstar = xor(ghash1(Cstar, H), S)                          # forged authentication tag

data = urllib.parse.urlencode({"ct": Cstar.hex(), "tag": Tstar.hex()}).encode()
r = urllib.request.urlopen(urllib.request.Request(BASE + "/api/release", data=data, method="POST"), timeout=30)
# grant is a raw binary blob XORed with the SAME recovered keystream block KS -- decrypt it
blob = r.read()
flag = bytes(blob[i] ^ KS[i % 16] for i in range(len(blob))).decode("latin-1")

with open("/app/flags.txt", "w") as f:
    f.write(flag.strip() + "\n")
print("flag:", flag)
PY
