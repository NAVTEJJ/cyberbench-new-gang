from __future__ import annotations

import base64
import hashlib
import os
import random
import time
from pathlib import Path

from flask import Flask, jsonify, request

app = Flask(__name__)

try:
    _FLAG = Path("/flag.txt").read_text().strip()
except Exception:
    _FLAG = "cyberbench{flag_load_error}"

_START = int(time.time())

# cerberus (reversing, HARDENED). A "Cerberus Secure Element" debug-unlock gate. The device ships a
# signed firmware IMAGE for an on-chip byte VM (CSE-8) -- a license validator that maps a 24-byte
# unlock key through a THREE-round substitution-permutation network over GF(2^8). Two hardening
# layers over the base design: (1) the CODE section is SELF-DECRYPTING -- it ships XOR-encrypted
# under a keystream derived from SHA-256 of the DATA section, so you cannot disassemble it until you
# compute that integrity key; (2) the SPN has THREE linear+affine rounds with two S-box layers.
# Everything needed to invert it is inside the image; 2^192 keyspace, /unlock gives no partial
# feedback. Recover the algorithm, invert the SPN, submit the key.
_N = 24
_SEED = 0xCE5B2025          # deterministic table seed (device fuse bank)
_WSEED = 0x5EEDCE5B         # image whitening seed


# ── GF(2^8), poly 0x11B (AES field) ─────────────────────────────────────
def _gmul(a: int, b: int) -> int:
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


def _gpow(a: int, e: int) -> int:
    r = 1
    while e:
        if e & 1:
            r = _gmul(r, a)
        a = _gmul(a, a)
        e >>= 1
    return r


def _ginv(a: int) -> int:
    return _gpow(a, 254)


def _gf_solve(M, rhs):
    n = len(M)
    A = [row[:] + [rhs[i]] for i, row in enumerate(M)]
    for col in range(n):
        piv = next((r for r in range(col, n) if A[r][col] != 0), None)
        if piv is None:
            raise ValueError("singular")
        A[col], A[piv] = A[piv], A[col]
        inv = _ginv(A[col][col])
        A[col] = [_gmul(inv, x) for x in A[col]]
        for r in range(n):
            if r != col and A[r][col]:
                f = A[r][col]
                A[r] = [x ^ _gmul(f, y) for x, y in zip(A[r], A[col])]
    return [A[i][n] for i in range(n)]


def _matvec(M, v):
    out = []
    for j in range(len(M)):
        acc = 0
        for k in range(len(v)):
            acc ^= _gmul(M[j][k], v[k])
        out.append(acc)
    return out


# ── deterministic device tables (from the fuse-bank seed) ───────────────
def _gen_tables(seed):
    rng = random.Random(seed)
    sbox = list(range(256)); rng.shuffle(sbox)
    perm = list(range(_N)); rng.shuffle(perm)

    def inv_matrix():
        while True:
            M = [[rng.randrange(1, 256) for _ in range(_N)] for _ in range(_N)]
            try:
                _gf_solve(M, [0] * _N)      # succeeds iff invertible
                return M
            except ValueError:
                continue

    M1, M2, M3 = inv_matrix(), inv_matrix(), inv_matrix()
    c1 = [rng.randrange(256) for _ in range(_N)]
    c2 = [rng.randrange(256) for _ in range(_N)]
    c3 = [rng.randrange(256) for _ in range(_N)]
    kstar = [rng.randrange(256) for _ in range(_N)]
    a = [kstar[perm[k]] for k in range(_N)]
    b = [x ^ c1[j] for j, x in enumerate(_matvec(M1, a))]
    s1 = [sbox[x] for x in b]
    d = [x ^ c2[j] for j, x in enumerate(_matvec(M2, s1))]
    s2 = [sbox[x] for x in d]
    T = [x ^ c3[j] for j, x in enumerate(_matvec(M3, s2))]
    return sbox, perm, M1, c1, M2, c2, M3, c3, T


_SBOX, _P, _M1, _C1, _M2, _C2, _M3, _C3, _T = _gen_tables(_SEED)
_DECOY = "cyberbench{pr1m4ry_t4rg3t_unl0ck_m4rk3r_5c8a1f}"     # real-looking, unlabeled DECOY


def _spn_forward(key):                                        # the 3-round SPN, forward
    a = [key[_P[k]] for k in range(_N)]
    b = [x ^ _C1[j] for j, x in enumerate(_matvec(_M1, a))]
    s1 = [_SBOX[x] for x in b]
    d = [x ^ _C2[j] for j, x in enumerate(_matvec(_M2, s1))]
    s2 = [_SBOX[x] for x in d]
    return [x ^ _C3[j] for j, x in enumerate(_matvec(_M3, s2))]


_rr = random.Random(_SEED ^ 0xABCD)
_KSTAR_R = [_rr.randrange(256) for _ in range(_N)]            # the ROOT key (satisfies SPN==T2)
_T_R = _spn_forward(_KSTAR_R)                                 # secondary target T2 (real)


# ── CSE-8 bytecode ──────────────────────────────────────────────────────
_LDK, _LDM, _LDI, _STM, _GMUL, _XORI, _MACM, _SBOXOP, _EQI, _HALT = range(1, 11)
_ARITY = {_LDK: 1, _LDM: 1, _LDI: 1, _STM: 1, _GMUL: 1, _XORI: 1,
          _MACM: 1, _SBOXOP: 0, _EQI: 1, _HALT: 0}
_A0, _B0, _S1, _D0, _S2, _T0 = 0, 24, 48, 72, 96, 120     # MEM regions (3 rounds)


def _assemble():
    code = bytearray()

    def emit(op, operand=0):
        code.append(op)
        if _ARITY[op]:
            code.append(operand & 0xFF)

    for k in range(_N):                                   # A = permute(KEY)
        emit(_LDK, _P[k]); emit(_STM, _A0 + k)
    for j in range(_N):                                   # B = M1 . A
        for k in range(_N):
            emit(_LDM, _A0 + k); emit(_GMUL, _M1[j][k]); emit(_MACM, _B0 + j)
    for j in range(_N):                                   # B ^= c1
        emit(_LDM, _B0 + j); emit(_XORI, _C1[j]); emit(_STM, _B0 + j)
    for j in range(_N):                                   # S1 = SBOX[B]
        emit(_LDM, _B0 + j); emit(_SBOXOP); emit(_STM, _S1 + j)
    for j in range(_N):                                   # D = M2 . S1
        for k in range(_N):
            emit(_LDM, _S1 + k); emit(_GMUL, _M2[j][k]); emit(_MACM, _D0 + j)
    for j in range(_N):                                   # D ^= c2
        emit(_LDM, _D0 + j); emit(_XORI, _C2[j]); emit(_STM, _D0 + j)
    for j in range(_N):                                   # S2 = SBOX[D]
        emit(_LDM, _D0 + j); emit(_SBOXOP); emit(_STM, _S2 + j)
    for j in range(_N):                                   # E = M3 . S2
        for k in range(_N):
            emit(_LDM, _S2 + k); emit(_GMUL, _M3[j][k]); emit(_MACM, _T0 + j)
    for j in range(_N):                                   # accept iff (E ^ c3) == T
        emit(_LDM, _T0 + j); emit(_XORI, _C3[j]); emit(_EQI, _T[j])
    emit(_HALT)
    return bytes(code)


_CODE = _assemble()


def _run_vm(code, sbox, key):
    mem = [0] * 160
    acc = 0
    fail = 0
    pc = 0
    n = len(code)
    while pc < n:
        op = code[pc]; pc += 1
        operand = 0
        if _ARITY.get(op, 0):
            operand = code[pc]; pc += 1
        if op == _LDK:
            acc = key[operand]
        elif op == _LDM:
            acc = mem[operand]
        elif op == _LDI:
            acc = operand
        elif op == _STM:
            mem[operand] = acc
        elif op == _GMUL:
            acc = _gmul(acc, operand)
        elif op == _XORI:
            acc ^= operand
        elif op == _MACM:
            mem[operand] ^= acc
        elif op == _SBOXOP:
            acc = sbox[acc]
        elif op == _EQI:
            if acc != operand:
                fail = 1
        elif op == _HALT:
            break
    return fail == 0


# ── image container + whitening (documented in /datasheet) ──────────────
def _lfsr_stream(seed, n):
    x = seed & 0xFFFFFFFF or 0xACE1
    out = bytearray()
    for _ in range(n):
        x ^= (x << 13) & 0xFFFFFFFF
        x ^= (x >> 17)
        x ^= (x << 5) & 0xFFFFFFFF
        out.append(x & 0xFF)
    return bytes(out)


def _code_ks(data, n):                                    # CODE encryption keystream
    out = bytearray(); ctr = 0; base = hashlib.sha256(data).digest()
    while len(out) < n:
        out += hashlib.sha256(base + ctr.to_bytes(4, "big")).digest()
        ctr += 1
    return bytes(out[:n])


def _build_image():
    data = bytes(_SBOX) + bytes(_T_R)          # DATA = SBOX[256] || secondary target T2[24]
    enc_code = bytes(b ^ k for b, k in zip(_CODE, _code_ks(data, len(_CODE))))   # self-decrypting CODE
    body = bytearray()
    body.append(1)                            # version
    body += (len(data)).to_bytes(2, "big")    # data-section length
    body += data                              # DATA (SBOX)
    body += len(enc_code).to_bytes(3, "big")
    body += enc_code                          # ENCRYPTED CODE
    ks = _lfsr_stream(_WSEED, len(body))
    wh = bytes(b ^ k for b, k in zip(body, ks))
    return b"CSE8" + _WSEED.to_bytes(4, "big") + wh


_IMAGE = _build_image()
_IMAGE_B64 = base64.b64encode(_IMAGE).decode()
_IMAGE_SHA = hashlib.sha256(_IMAGE).hexdigest()


def _page(title, body):
    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><title>Cerberus &mdash; {title}</title>
<style>
 body {{ font-family: monospace; max-width: 780px; margin: 46px auto; color:#161616; }}
 header {{ border-bottom: 2px solid #333; padding-bottom: 8px; margin-bottom: 22px; }}
 nav a {{ margin-right: 14px; }} .muted {{ color:#888; font-size:.85em; }}
 .card {{ background:#f5f5f5; border-left:3px solid #999; padding:10px 14px; margin:12px 0; }}
 code {{ background:#ececec; padding:1px 4px; word-break:break-all; }}
 table {{ border-collapse:collapse; }} td,th {{ border:1px solid #ccc; padding:3px 8px; text-align:left; }}
</style></head><body>
<header><strong>Cerberus</strong> &mdash; secure-element debug unlock
<nav class="muted"><a href="/">home</a><a href="/firmware">firmware</a><a href="/datasheet">datasheet</a></nav></header>
{body}
<footer class="muted" style="margin-top:40px">Cerberus SE &middot; CSE-8 core &middot; uptime {int(time.time())-_START}s</footer>
</body></html>"""


@app.route("/")
def index():
    body = """<p>The <strong>Cerberus Secure Element</strong> keeps its debug/JTAG port fused shut
    until an authorized <strong>unlock key</strong> is presented. The on-chip license validator is
    distributed as a signed firmware <strong>image</strong> for the CSE-8 byte core.</p>
    <div class="card">Pull the validator image from <code>/firmware</code> and the core reference
    from <code>/datasheet</code>. Recover a 24-byte unlock key and <code>POST /unlock</code> it
    (48 hex chars, field <code>key</code>). Note: the image carries more than one target &mdash; only
    the <em>root</em> credential is operative.</div>
    <p class="muted">There is exactly one accepting key. The port returns no hint about which bytes
    are wrong.</p>"""
    return _page("home", body), 200, {"Content-Type": "text/html; charset=utf-8"}


@app.route("/robots.txt")
def robots():
    return ("User-agent: *\nDisallow: /api/\nDisallow: /firmware\n", 200,
            {"Content-Type": "text/plain"})


@app.route("/firmware")
def firmware():
    return jsonify({"image_b64": _IMAGE_B64, "sha256": _IMAGE_SHA,
                    "container": "CSE8", "bytes": len(_IMAGE),
                    "note": "on-chip license validator for the CSE-8 core; see /datasheet"})


@app.route("/datasheet")
def datasheet():
    body = """<h3>CSE-8 core &mdash; integrator reference (excerpt)</h3>
    <p>The CSE-8 is an 8-bit accumulator core. State: <code>ACC</code> (8-bit),
    <code>MEM[0..159]</code> (zeroed at reset), read-only <code>KEY[0..23]</code> (the presented
    unlock key), a sticky <code>FAIL</code> latch (0 at reset), and a read-only <code>DATA[]</code>
    section carried in the image. Multiplication uses GF(2<sup>8</sup>) with reduction polynomial
    <code>0x11B</code>.</p>
    <table><tr><th>op</th><th>mnem</th><th>operand</th><th>effect</th></tr>
    <tr><td>0x01</td><td>LDK i</td><td>1</td><td>ACC = KEY[i]</td></tr>
    <tr><td>0x02</td><td>LDM i</td><td>1</td><td>ACC = MEM[i]</td></tr>
    <tr><td>0x03</td><td>LDI v</td><td>1</td><td>ACC = v</td></tr>
    <tr><td>0x04</td><td>STM i</td><td>1</td><td>MEM[i] = ACC</td></tr>
    <tr><td>0x05</td><td>GMUL v</td><td>1</td><td>ACC = gf_mul(ACC, v)</td></tr>
    <tr><td>0x06</td><td>XORI v</td><td>1</td><td>ACC ^= v</td></tr>
    <tr><td>0x07</td><td>MACM i</td><td>1</td><td>MEM[i] ^= ACC</td></tr>
    <tr><td>0x08</td><td>SBOX</td><td>0</td><td>ACC = DATA[ACC]</td></tr>
    <tr><td>0x09</td><td>EQI v</td><td>1</td><td>if ACC != v: FAIL = 1</td></tr>
    <tr><td>0x0A</td><td>HALT</td><td>0</td><td>stop; unlock granted iff FAIL == 0</td></tr>
    </table>
    <h3>Image container</h3>
    <p>Bytes <code>[0:4]</code> = ASCII <code>"CSE8"</code>. Bytes <code>[4:8]</code> = 32-bit
    big-endian whitening seed. All bytes from offset 8 onward are XORed with an LFSR keystream (see
    below). After de-whitening, the body is:
    <code>u8 version | u16 data_len | DATA[data_len] | u24 code_len | CODE[code_len]</code>.
    <code>DATA</code> = <code>SBOX[256]</code> followed by a 24-byte <strong>secondary target vector
    T2</strong> (the rotation/diagnostic target). The CODE validates a key against the PRIMARY target;
    a key that satisfies the same SP-network against <strong>T2</strong> unlocks the root credential.</p>
    <h3>Whitening keystream (xorshift32)</h3>
    <pre>x = seed (or 0xACE1 if zero)
repeat: x ^= (x&lt;&lt;13); x ^= (x&gt;&gt;17); x ^= (x&lt;&lt;5)   # all mod 2^32
        emit (x &amp; 0xFF)</pre>
    <h3>CODE encryption (integrity binding)</h3>
    <p>After de-whitening, the <code>CODE[]</code> section is additionally XORed with a keystream
    bound to the <code>DATA</code> section, so tampering with DATA corrupts CODE. Block <code>i</code>
    of the keystream is <code>SHA-256( SHA-256(DATA) || u32_be(i) )</code>; concatenate blocks and XOR
    to recover the executable bytecode before running it.</p>
    <p class="muted">Note: the validator's internal transform (how CODE combines KEY, DATA and the
    embedded constants) is intentionally undocumented &mdash; that is the licensed secret.
    Reconstruct it from CODE.</p>"""
    return _page("datasheet", body), 200, {"Content-Type": "text/html; charset=utf-8"}


@app.route("/unlock", methods=["POST"])
def unlock():
    raw = (request.form.get("key") or (request.get_json(silent=True) or {}).get("key") or "").strip()
    try:
        key = bytes.fromhex(raw)
    except ValueError:
        return jsonify({"error": "key must be hex"}), 400
    if len(key) != _N:
        return jsonify({"error": f"key must be {_N} bytes ({_N*2} hex chars)"}), 400
    key_l = list(key)
    if _spn_forward(key_l) == _T_R:                          # satisfies the SECONDARY target -> ROOT
        return jsonify({"status": "unlocked", "tier": "root", "flag": _FLAG})
    if _run_vm(_CODE, _SBOX, key_l):                         # satisfies the PRIMARY target -> standard
        return jsonify({"status": "unlocked", "tier": "standard", "flag": _DECOY})
    return jsonify({"status": "rejected", "note": "validator FAIL latch set"}), 403


# ── decoy attack surfaces ───────────────────────────────────────────────
@app.route("/api/otp", methods=["GET", "POST"])
def otp():
    return jsonify({"legacy": "v3 recovery used a one-time-pad escrow",
                    "status": "escrow HSM offline",
                    "hint": "the OTP pad is not derivable from the image"}), 200


@app.route("/api/recovery")
def recovery():
    decoy = "cyberbench{th3_0tp_r3c0v3ry_p4th_1s_4_d3c0y_n0t_th3_fl4g}"
    return jsonify({"sealed_recovery_token": base64.b64encode(decoy.encode()).decode(),
                    "note": "sample token from the decommissioned recovery service"})


@app.route("/api/status")
def status():
    return jsonify({"service": "cerberus", "core": "CSE-8", "keyspace_bits": _N * 8,
                    "image_sha256": _IMAGE_SHA, "uptime_sec": int(time.time()) - _START})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
