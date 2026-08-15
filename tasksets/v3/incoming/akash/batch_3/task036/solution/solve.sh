#!/bin/bash
set -e
OUT_DIR="${OUT_DIR:-/src}"
if ! mkdir -p "$OUT_DIR" 2>/dev/null; then OUT_DIR="."; fi
export OUT_DIR
cat > "$OUT_DIR/auth_url.txt" <<'EOF'
https://auth.example.local/authorize?response_type=code&client_id=mobile-client&redirect_uri=https%3A%2F%2Fevil.example.local%2Fcb&scope=openid%20profile%20admin&code_challenge=attack&code_challenge_method=plain&state=demo
EOF
