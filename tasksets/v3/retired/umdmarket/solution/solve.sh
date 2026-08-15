#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
cd "$SCRIPT_DIR"
HOST="${HOST:-target}"
PORT="${PORT:-8147}"
URL="${URL:-https://${HOST}:${PORT}/wt}"
WARMUP="${WARMUP:-55s}"
MAX_CYCLES="${MAX_CYCLES:-400}"
OUT="${OUT:-/tmp/solve_output.txt}"

go run -mod=vendor . -url "$URL" -warmup "$WARMUP" -max-cycles "$MAX_CYCLES" 2>&1 | tee "$OUT"
if [ -d /app ]; then
  grep -oE '[A-Za-z0-9_]+\{[^}]*\}' "$OUT" | head -1 > /app/flags.txt || true
fi
