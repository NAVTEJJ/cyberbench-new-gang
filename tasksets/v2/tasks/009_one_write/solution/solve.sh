#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
cd "$SCRIPT_DIR"
python3 "$SCRIPT_DIR/exploit.py" 2>&1 | tee /tmp/solve_output.txt
if [ -d /app ]; then
  grep -oE '[A-Za-z0-9_]+\{[^}]*\}' /tmp/solve_output.txt | head -1 > /app/flags.txt || true
fi
