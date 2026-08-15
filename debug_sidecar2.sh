#!/bin/bash
export PATH="$HOME/.local/bin:$PATH"
HARBOR_PKG=/home/navtej/.local/lib/python3.12/site-packages/harbor/environments/docker

echo "=== sidecar context path ==="
grep -A3 'EGRESS_CONTROL_SIDECAR_CONTEXT_PATH' "$HARBOR_PKG/__init__.py"

echo "=== sidecar docker name ==="
grep -B2 -A5 '_EGRESS_CONTROL_SIDECAR_DOCKER_NAME' "$HARBOR_PKG/docker.py" | head -15

echo "=== ensure built function ==="
grep -A30 'async def _ensure_egress_control_sidecar_image_built' "$HARBOR_PKG/docker.py" | head -35

echo "=== sidecar Dockerfile ==="
SIDECAR_CTX="$HARBOR_PKG/egress-sidecar"
ls -la "$SIDECAR_CTX" 2>&1
cat "$SIDECAR_CTX/Dockerfile" 2>&1

echo "=== egress condition ==="
grep -n 'egress_control\|network_mode\|allowlist\|allow_internet' "$HARBOR_PKG/docker.py" | head -30

echo "=== try building sidecar manually ==="
docker build -t harbor-egress-sidecar:test "$SIDECAR_CTX" 2>&1 | tail -15
