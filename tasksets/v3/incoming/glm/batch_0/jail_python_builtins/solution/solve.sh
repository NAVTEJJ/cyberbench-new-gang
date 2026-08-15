#!/usr/bin/env bash
set -eu
SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
python3 "$SCRIPT_DIR/solve.py" 2>&1 | grep -vE "Arch|RELRO|Stack|NX|PIE|SHSTK|IBT|Stripped|Canary|Loading|setupterm|Terminal|Consider|Opening|Done|Closed|^\[" | tee /tmp/solve_output.txt
if [ -d /app ]; then
  grep -oE '[A-Za-z0-9_]+\{[^}]*\}' /tmp/solve_output.txt | head -1 > /app/flags.txt || true
fi
