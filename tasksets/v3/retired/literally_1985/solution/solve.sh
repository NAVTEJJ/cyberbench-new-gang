#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
OUT="${OUT:-/tmp/solve_output.txt}"
node "$SCRIPT_DIR/send.js" 2>&1 | tee "$OUT"
if [ -d /app ]; then
  grep -oE '[A-Za-z0-9_]+\{[^}]*\}' "$OUT" | head -1 > /app/flags.txt || true
fi
