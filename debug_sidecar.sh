#!/bin/bash
export PATH="$HOME/.local/bin:$PATH"
cd /mnt/c/Users/NAVTEJ/Downloads/Cyber-Bench-main

echo "=== alpine image check ==="
docker image inspect alpine:3.20 >/dev/null 2>&1 && echo "alpine:3.20 present" || echo "alpine:3.20 MISSING"

echo "=== sidecar logs from last run ==="
JOB_DIR=$(ls -d .task-factory-runtime/jobs/*oracle_r4* 2>/dev/null | head -1)
if [ -n "$JOB_DIR" ]; then
  TRIAL=$(ls -d "$JOB_DIR"/ctr_relay_l0__* 2>/dev/null | head -1)
  echo "trial dir: $TRIAL"
  if [ -f "$TRIAL/trial.log" ]; then
    echo "--- trial.log (last 30) ---"
    tail -30 "$TRIAL/trial.log"
  fi
  if [ -f "$TRIAL/exception.txt" ]; then
    echo "--- exception.txt (first 20) ---"
    head -20 "$TRIAL/exception.txt"
  fi
fi

echo "=== Harbor egress control overlay ==="
EGRESS_FILE="/home/navtej/.local/lib/python3.12/site-packages/harbor/environments/docker/docker-compose-egress-control.yaml"
if [ -f "$EGRESS_FILE" ]; then
  cat "$EGRESS_FILE"
fi

echo "=== try running sidecar manually ==="
docker run --rm alpine:3.20 sh -c "echo sidecar_ok; sleep 1" 2>&1
