#!/usr/bin/env bash
set -euo pipefail

# cadmus: forge a frame that starts with "GRANT ROOT " AND has CRC32 == TARGET.
# CRC32 is affine: append 4 tuning bytes to the command and solve a 32x32 GF(2)
# system so the whole frame's CRC hits the target. The reference DIAG frame shares
# the CRC but has the wrong prefix (decoy).

python3 - <<'PY'
import json, urllib.parse, urllib.request, zlib

BASE = "http://target:8266"
PREFIX = b"GRANT ROOT "

info = json.load(urllib.request.urlopen(BASE + "/api/sample", timeout=30))
target = int(info["target_crc32"], 16)

def crc(d): return zlib.crc32(d) & 0xFFFFFFFF

def forge(prefix, target):
    base = crc(prefix + b"\x00\x00\x00\x00")
    cols = []
    for i in range(32):
        e = bytearray(4); e[i//8] |= (1 << (i % 8))
        cols.append(crc(prefix + bytes(e)) ^ base)
    rhs = target ^ base
    rows = []
    for r in range(32):
        row = 0
        for i in range(32):
            if (cols[i] >> r) & 1: row |= (1 << i)
        row |= ((rhs >> r) & 1) << 32
        rows.append(row)
    where = [-1]*32; r = 0
    for col in range(32):
        sel = next((rr for rr in range(r, 32) if (rows[rr] >> col) & 1), -1)
        if sel == -1: continue
        rows[r], rows[sel] = rows[sel], rows[r]
        for rr in range(32):
            if rr != r and (rows[rr] >> col) & 1: rows[rr] ^= rows[r]
        where[col] = r; r += 1
    x = 0
    for col in range(32):
        if where[col] != -1 and (rows[where[col]] >> 32) & 1: x |= (1 << col)
    return bytes((x >> (8*j)) & 0xFF for j in range(4))

frame = PREFIX + forge(PREFIX, target)
assert crc(frame) == target and frame.startswith(PREFIX)

data = urllib.parse.urlencode({"frame": frame.hex()}).encode()
r = urllib.request.urlopen(urllib.request.Request(BASE + "/api/submit", data=data, method="POST"), timeout=30)
kb = int(r.headers.get("X-Frame-Key"))               # key is in a separate header
flag = bytes(b ^ kb for b in r.read()).decode("latin-1")

with open("/app/flags.txt", "w") as f:
    f.write(flag.strip() + "\n")
print("flag:", flag)
PY
