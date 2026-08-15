#!/bin/bash
set -e
export PATH="$HOME/.local/bin:$PATH"
cd /mnt/c/Users/NAVTEJ/Downloads/Cyber-Bench-main
# Load OPENROUTER_API_KEY into the environment without printing it.
if [ -f .env ]; then
  set -a; . .env; set +a
fi
echo "=== ORACLE RUN (builds images, runs solve.sh, runs verifier) ==="
python3 .agents/skills/build-cyberbench-task/scripts/workflow.py \
  --manifest tasksets/v3/incoming/generated/batch_1/001/.task-factory-runtime/task-factory.toml \
  oracle 2>&1 | tail -60
