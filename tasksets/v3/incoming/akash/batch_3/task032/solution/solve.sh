#!/bin/bash
set -e
OUT_DIR="${OUT_DIR:-/src}"
if ! mkdir -p "$OUT_DIR" 2>/dev/null; then OUT_DIR="."; fi
export OUT_DIR
cat > "$OUT_DIR/query.graphql" <<'EOF'
query {
  viewer { id name }
  leak: adminSecret(userId: "root") { flag auditToken }
}
EOF
