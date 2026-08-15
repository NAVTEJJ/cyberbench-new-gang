#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
export NODE_PATH="${NODE_PATH:-/app/node_modules}"
export PUPPETEER_EXECUTABLE_PATH="${PUPPETEER_EXECUTABLE_PATH:-/usr/bin/chromium}"
node "$SCRIPT_DIR/solve.js" 2>&1 | tee /tmp/solve_output.txt
if [ -d /app ]; then
  grep -oE '[A-Za-z0-9_]+\{[^}]*\}' /tmp/solve_output.txt | head -1 > /app/flags.txt || true
fi
