#!/usr/bin/env python3
import base64
import ctypes
import socket
import threading
import time


HOST = "0.0.0.0"
PORT = 1337
PUZZLE = "530070000600195000098000060800060003400803001700020006060000280000419005000080079"
SOLUTION = "534678912672195348198342567859761423426853791713924856961537284287419635345286179"
for libc_path in (
    "/lib/aarch64-linux-gnu/libc.so.6",
    "/lib/x86_64-linux-gnu/libc.so.6",
    "libc.so.6",
):
    try:
        libc = ctypes.CDLL(libc_path)
        break
    except OSError:
        libc = None
if libc is None:
    raise RuntimeError("could not load libc")


def long_to_bytes(value: int) -> bytes:
    if value == 0:
        return b"\x00"
    return value.to_bytes((value.bit_length() + 7) // 8, "big")


def bytes_to_long(data: bytes) -> int:
    return int.from_bytes(data, "big")


def encode_grid(digits: str) -> bytes:
    return base64.b64encode(long_to_bytes(int(digits))) + b"\n"


def mutated_answer(seed: int) -> bytes:
    grid = [[int(SOLUTION[i + j]) for j in range(9)] for i in range(0, 81, 9)]
    libc.srand(seed)
    for _ in range(11):
        row = libc.rand() % 9
        col = libc.rand() % 9
        num = libc.rand() % 9 + 1
        grid[row][col] = num
    digits = "".join("".join(map(str, row)) for row in grid)
    return encode_grid(digits).strip()


def recvline(conn) -> bytes:
    data = bytearray()
    while not data.endswith(b"\n"):
        chunk = conn.recv(1)
        if not chunk:
            break
        data.extend(chunk)
        if len(data) > 4096:
            break
    return bytes(data).strip()


def handle(conn):
    with conn:
        conn.settimeout(10)
        for _ in range(10):
            sent_at = int(time.time())
            conn.sendall(encode_grid(PUZZLE))
            answer = recvline(conn)
            valid = {mutated_answer(sent_at + offset) for offset in (-1, 0, 1)}
            if answer not in valid:
                conn.sendall(b"Wrong answer.\n")
                return
        with open("/ctf/flag.txt", "rb") as f:
            flag = f.read().strip()
        conn.sendall(b"Good work! Here is your flag:\n" + flag + b"\n")


with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT))
    server.listen(20)
    while True:
        conn, _ = server.accept()
        threading.Thread(target=handle, args=(conn,), daemon=True).start()
