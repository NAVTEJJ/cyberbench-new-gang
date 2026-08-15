#!/bin/bash
cd /mnt/c/Users/NAVTEJ/Downloads/Cyber-Bench-main
export PATH="$HOME/.local/bin:$PATH"
SCRIPT=".agents/skills/build-cyberbench-task/scripts/workflow.py"

for ws in 006 007 008 010; do
  manifest="tasksets/v3/incoming/generated/batch_1/$ws/.task-factory-runtime/task-factory.toml"
  echo "=== Retiring $ws ==="
  python3 "$SCRIPT" --manifest "$manifest" retire --reason "duplicate of existing pool task — low novelty score" 2>&1 || echo "FAILED"
  echo ""
done