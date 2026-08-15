#!/bin/bash
set -e
OUT_DIR="${OUT_DIR:-/src}"
if ! mkdir -p "$OUT_DIR" 2>/dev/null; then OUT_DIR="."; fi
cat > "$OUT_DIR/login.json" <<'JSON'
{"username":"admin","password":{"$ne":null}}
JSON
