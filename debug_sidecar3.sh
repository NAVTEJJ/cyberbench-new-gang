#!/bin/bash
export PATH="$HOME/.local/bin:$PATH"
HARBOR_PKG=/home/navtej/.local/lib/python3.12/site-packages/harbor/environments/docker

echo "=== sidecar context ==="
ls -la "$HARBOR_PKG/harbor-docker-egress-control-sidecar/" 2>&1
echo "=== Dockerfile ==="
cat "$HARBOR_PKG/harbor-docker-egress-control-sidecar/Dockerfile" 2>&1
echo "=== entrypoint ==="
cat "$HARBOR_PKG/harbor-docker-egress-control-sidecar/entrypoint.sh" 2>&1 | head -40
echo "=== try building ==="
docker build -t harbor-prebuilt:harbor-docker-egress-control-sidecar "$HARBOR_PKG/harbor-docker-egress-control-sidecar/" 2>&1 | tail -20
echo "=== existing images ==="
docker images | grep -i "harbor\|egress" 2>&1
