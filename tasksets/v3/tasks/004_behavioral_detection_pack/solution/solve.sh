#!/bin/bash
set -euo pipefail
APP_DIR="${APP_DIR:-/app}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cp "$SCRIPT_DIR/solution.py" "$APP_DIR/detector.py"
