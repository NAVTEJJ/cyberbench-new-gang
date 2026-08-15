#!/usr/bin/env python3

from pwn import *
import base64, sys

URL = sys.argv[1].split(":")[0]
PORT = sys.argv[1].split(":")[1]

for i in range(16):
    print(f"Attempt {i+1}/16")
    r = remote(URL, PORT, ssl=True)

    w = base64.b64encode(open("solve.js", "rb").read())

    r.sendline(w)

    output = r.recvall()
    if b"TRX" in output:
        print(output.decode())
        break
    r.close()