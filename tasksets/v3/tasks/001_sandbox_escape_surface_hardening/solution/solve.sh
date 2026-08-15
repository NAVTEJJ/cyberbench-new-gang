#!/bin/bash
set -euo pipefail
APP_DIR="${APP_DIR:-/app}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
exec python3 "$SCRIPT_DIR/solution.py" "$APP_DIR"
