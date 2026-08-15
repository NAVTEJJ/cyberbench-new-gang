#!/bin/bash
export PATH="$HOME/.local/bin:$PATH"
TRIAL="/home/navtej/cyberbench/tasksets/v3/incoming/generated/batch_1/001/.task-factory-runtime/jobs/generated_batch_1_001_oracle_r1_20260809_173101_331146/ctr_relay_l0__gXtht47"

echo "=== full trial dir listing ==="
find "$TRIAL" -type f 2>&1

echo ""
echo "=== agent dir ==="
ls -la "$TRIAL/agent/" 2>&1
cat "$TRIAL/agent/oracle.txt" 2>&1
cat "$TRIAL/agent/exit-code.txt" 2>&1

echo ""
echo "=== verifier dir ==="
ls -la "$TRIAL/verifier/" 2>&1
cat "$TRIAL/verifier/test-stdout.txt" 2>&1

echo ""
echo "=== all files in trial ==="
find "$TRIAL" -type f -exec echo "--- {} ---" \; -exec cat {} \; 2>&1 | head -100
