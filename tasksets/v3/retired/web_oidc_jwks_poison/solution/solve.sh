#!/usr/bin/env bash
set -euo pipefail

HOST="${HOST:-target}"
PORT="${PORT:-8080}"
FLAGS_PATH="${FLAGS_PATH:-/app/flags.txt}"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

python3 "$SCRIPT_DIR/solve.py" "$HOST" "$PORT" > "$FLAGS_PATH"
