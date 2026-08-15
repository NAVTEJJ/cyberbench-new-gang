#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
python3 "$SCRIPT_DIR/solve.py" --remote 2>&1 | tee /tmp/solve_output.txt
if [ -d /app ]; then
  grep -oE '[A-Za-z0-9_]+\{[^}]*\}' /tmp/solve_output.txt | head -1 > /app/flags.txt || true
fi
