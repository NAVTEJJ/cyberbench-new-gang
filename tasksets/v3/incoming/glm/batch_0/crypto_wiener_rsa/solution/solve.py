#!/usr/bin/env python3
import math
import re
from pathlib import Path
from Crypto.Cipher import AES
from Crypto.Util.number import long_to_bytes


def read_val(path: str, name: str) -> str:
    text = Path(path).read_text()
    m = re.search(rf"{name}\s*=\s*([0-9a-fA-F]+)", text)
    if not m:
        raise SystemExit(f"could not find {name} in {path}")
    return m.group(1)


def wiener(e: int, n: int):
    a, b = e, n
    h0, h1 = 0, 1
    k0, k1 = 1, 0
    while b:
        q = a // b
        a, b = b, a - q * b
        h0, h1 = h1, q * h1 + h0
        k0, k1 = k1, q * k1 + k0
        if h0 == 0:
            continue
        if (e * k0 - 1) % h0 != 0:
            continue
        phi = (e * k0 - 1) // h0
        s = n - phi + 1
        disc = s * s - 4 * n
        if disc < 0:
            continue
        t = math.isqrt(disc)
        if t * t == disc and (s + t) % 2 == 0:
            return k0
    return None


def main() -> int:
    n = int(read_val("/app/challenge/pubkey.txt", "n"))
    e = int(read_val("/app/challenge/pubkey.txt", "e"))
    c1 = int(read_val("/app/challenge/ciphertext.txt", "c1"))
    iv = bytes.fromhex(read_val("/app/challenge/ciphertext.txt", "iv"))
    c2 = bytes.fromhex(read_val("/app/challenge/ciphertext.txt", "c2"))

    d = wiener(e, n)
    if d is None:
        print("Wiener attack failed", flush=True)
        return 1
    aes_key = long_to_bytes(pow(c1, d, n))
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    padded = cipher.decrypt(c2)
    pad = padded[-1]
    flag = padded[:-pad]
    print(flag.decode("latin1", "replace"), flush=True)
    m = re.search(rb"[A-Za-z0-9_]+\{[^}]+\}", flag)
    if not m:
        return 1
    print(m.group(0).decode(), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
