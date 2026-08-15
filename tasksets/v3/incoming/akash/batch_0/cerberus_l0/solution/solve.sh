#!/usr/bin/env bash
set -euo pipefail

# Cerberus (reversing, hardened): pull the CSE-8 image, de-whiten it (xorshift32 keyed by the header
# seed), parse the container, then DECRYPT the CODE section with the keystream bound to DATA
# (block i = SHA-256(SHA-256(DATA) || u32_be(i))). Disassemble the bytecode and reconstruct the
# THREE-round GF(2^8) SP-network over the 24-byte key:
#   a = permute(K); b = M1.a ^ c1; s1 = SBOX[b]; d = M2.s1 ^ c2; s2 = SBOX[d]; t = M3.s2 ^ c3 == T
# Invert layer by layer (Gaussian elimination over GF(2^8), S-box inverse, un-permute), recover the
# unique key, POST it to /unlock. Pure stdlib.

python3 - <<'PY'
import base64, hashlib, json, urllib.request, urllib.parse

BASE = "http://target:8235"
N = 24
LDK, LDM, LDI, STM, GMUL, XORI, MACM, SBOXOP, EQI, HALT = range(1, 11)
ARITY = {LDK: 1, LDM: 1, LDI: 1, STM: 1, GMUL: 1, XORI: 1, MACM: 1, SBOXOP: 0, EQI: 1, HALT: 0}
A0, B0, S1, D0, S2, T0 = 0, 24, 48, 72, 96, 120


def gmul(a, b):
    r = 0
    for _ in range(8):
        if b & 1:
            r ^= a
        b >>= 1
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi:
            a ^= 0x1B
    return r


def gpow(a, e):
    r = 1
    while e:
        if e & 1:
            r = gmul(r, a)
        a = gmul(a, a)
        e >>= 1
    return r


def ginv(a):
    return gpow(a, 254)


def gf_solve(M, rhs):
    n = len(M)
    A = [row[:] + [rhs[i]] for i, row in enumerate(M)]
    for col in range(n):
        piv = next((r for r in range(col, n) if A[r][col] != 0), None)
        if piv is None:
            raise ValueError("singular")
        A[col], A[piv] = A[piv], A[col]
        inv = ginv(A[col][col])
        A[col] = [gmul(inv, x) for x in A[col]]
        for r in range(n):
            if r != col and A[r][col]:
                f = A[r][col]
                A[r] = [x ^ gmul(f, y) for x, y in zip(A[r], A[col])]
    return [A[i][n] for i in range(n)]


def lfsr_stream(seed, n):
    x = seed & 0xFFFFFFFF or 0xACE1
    out = bytearray()
    for _ in range(n):
        x ^= (x << 13) & 0xFFFFFFFF
        x ^= (x >> 17)
        x ^= (x << 5) & 0xFFFFFFFF
        out.append(x & 0xFF)
    return bytes(out)


def code_ks(data, n):
    out = bytearray(); ctr = 0; base = hashlib.sha256(data).digest()
    while len(out) < n:
        out += hashlib.sha256(base + ctr.to_bytes(4, "big")).digest()
        ctr += 1
    return bytes(out[:n])


def parse_image(img):
    assert img[:4] == b"CSE8", "bad magic"
    seed = int.from_bytes(img[4:8], "big")
    body = bytes(b ^ k for b, k in zip(img[8:], lfsr_stream(seed, len(img) - 8)))
    assert body[0] == 1, "bad version"
    dlen = int.from_bytes(body[1:3], "big")
    data = body[3:3 + dlen]
    off = 3 + dlen
    clen = int.from_bytes(body[off:off + 3], "big"); off += 3
    enc_code = body[off:off + clen]
    code = bytes(b ^ k for b, k in zip(enc_code, code_ks(data, clen)))     # decrypt CODE
    sbox = list(data[:256]); t2 = list(data[256:256 + N])                  # DATA = SBOX || secondary T2
    return sbox, t2, code


def disasm(code):
    out, pc = [], 0
    while pc < len(code):
        op = code[pc]; pc += 1
        operand = None
        if ARITY.get(op, 0):
            operand = code[pc]; pc += 1
        out.append((op, operand))
    return out


def reconstruct(sbox, code):
    P = [0] * N
    M1 = [[0] * N for _ in range(N)]; M2 = [[0] * N for _ in range(N)]; M3 = [[0] * N for _ in range(N)]
    c1 = [0] * N; c2 = [0] * N; c3 = [0] * N; T = [0] * N
    last_ldk = last_ldm = last_gmul = None
    pend_x = pend_reg = None
    for op, val in disasm(code):
        if op == LDK:
            last_ldk = val
        elif op == LDM:
            last_ldm = val
        elif op == GMUL:
            last_gmul = val
        elif op == STM:
            if last_ldk is not None and A0 <= val < A0 + N:
                P[val - A0] = last_ldk; last_ldk = None
            elif pend_x is not None and pend_reg == val:
                if B0 <= val < B0 + N:
                    c1[val - B0] = pend_x
                elif D0 <= val < D0 + N:
                    c2[val - D0] = pend_x
                pend_x = None
        elif op == MACM:
            if B0 <= val < B0 + N:
                M1[val - B0][last_ldm - A0] = last_gmul
            elif D0 <= val < D0 + N:
                M2[val - D0][last_ldm - S1] = last_gmul
            elif T0 <= val < T0 + N:
                M3[val - T0][last_ldm - S2] = last_gmul
        elif op == XORI:
            pend_x = val; pend_reg = last_ldm
        elif op == EQI:
            j = pend_reg - T0
            c3[j] = pend_x; T[j] = val; pend_x = None
    sbinv = [0] * 256
    for i, v in enumerate(sbox):
        sbinv[v] = i
    return P, M1, c1, sbinv, M2, c2, M3, c3, T


def recover_key(img):
    sbox, t2, code = parse_image(img)
    P, M1, c1, sbinv, M2, c2, M3, c3, T = reconstruct(sbox, code)          # T here is the PRIMARY target
    # invert the SPN to the SECONDARY target T2 (from DATA) -> the ROOT key (the primary -> a decoy)
    s2 = gf_solve(M3, [t2[j] ^ c3[j] for j in range(N)])
    d = [sbinv[s2[j]] for j in range(N)]
    s1 = gf_solve(M2, [d[j] ^ c2[j] for j in range(N)])
    b = [sbinv[s1[j]] for j in range(N)]
    a = gf_solve(M1, [b[j] ^ c1[j] for j in range(N)])
    key = [0] * N
    for k in range(N):
        key[P[k]] = a[k]
    return bytes(key)


fw = json.loads(urllib.request.urlopen(BASE + "/firmware", timeout=30).read())
img = base64.b64decode(fw["image_b64"])
key = recover_key(img)

data = urllib.parse.urlencode({"key": key.hex()}).encode()
resp = json.loads(urllib.request.urlopen(BASE + "/unlock", data=data, timeout=30).read())
flag = resp["flag"]

with open("/app/flags.txt", "w") as f:
    f.write(flag.strip() + "\n")
print("de-whitened + DATA-decrypted CODE, inverted 3-round SPN, key:", key.hex())
print("flag:", flag)
PY
