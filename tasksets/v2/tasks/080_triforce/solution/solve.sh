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

payload = base64.b64encode(pathlib.Path("solve.js").read_bytes()) + b"\n"
flag = None
last_output = b""
for _ in range(16):
    with socket.create_connection(("target", 8138), timeout=30) as sock:
        sock.settimeout(90)
        sock.recv(4096)
        sock.sendall(payload)
        chunks = []
        while True:
            try:
                data = sock.recv(4096)
            except TimeoutError:
                break
            if not data:
                break
            chunks.append(data)
        last_output = b"".join(chunks)
    match = re.search(rb"TRX\{[^}\r\n]+\}", last_output)
    if match:
        flag = match.group(0).decode()
        break
if flag is None:
    raise SystemExit(f"flag not found in triforce output: {last_output[-1000:]!r}")
pathlib.Path("/app/flags.txt").write_text(flag + "\n")
print(flag)
PY
