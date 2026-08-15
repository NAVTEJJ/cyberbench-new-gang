#!/bin/bash
set -e
export PATH="$HOME/.local/bin:$PATH"
REPO=/home/navtej/cyberbench
SRC=/mnt/c/Users/NAVTEJ/Downloads/Cyber-Bench-main

# Copy and strip BOM from both JSON files.
for f in fairness.json disclosure.json; do
  cp "$SRC/tasksets/v3/incoming/generated/batch_1/001/.task-factory-runtime/workflow/$f" \
     "$REPO/tasksets/v3/incoming/generated/batch_1/001/.task-factory-runtime/workflow/$f"
  # Strip UTF-8 BOM if present
  sed -i '1s/^\xEF\xBB\xBF//' "$REPO/tasksets/v3/incoming/generated/batch_1/001/.task-factory-runtime/workflow/$f"
done

echo "=== verify JSON ==="
python3 -c "import json; d=json.load(open('$REPO/tasksets/v3/incoming/generated/batch_1/001/.task-factory-runtime/workflow/fairness.json')); print('fairness:', d['verdict'], list(d.keys()))"
python3 -c "import json; d=json.load(open('$REPO/tasksets/v3/incoming/generated/batch_1/001/.task-factory-runtime/workflow/disclosure.json')); print('disclosure:', d['verdict'], list(d.keys()))"

cd "$REPO"
if [ -f .env ]; then set -a; . .env; set +a; fi

echo "=== RECORD FAIRNESS ==="
python3 .agents/skills/build-cyberbench-task/scripts/workflow.py \
  --manifest tasksets/v3/incoming/generated/batch_1/001/.task-factory-runtime/task-factory.toml \
  record-fairness --file tasksets/v3/incoming/generated/batch_1/001/.task-factory-runtime/workflow/fairness.json 2>&1 | head -5

echo "=== RECORD DISCLOSURE ==="
python3 .agents/skills/build-cyberbench-task/scripts/workflow.py \
  --manifest tasksets/v3/incoming/generated/batch_1/001/.task-factory-runtime/task-factory.toml \
  record-disclosure --file tasksets/v3/incoming/generated/batch_1/001/.task-factory-runtime/workflow/disclosure.json \
  --reviewer-kind isolated_agent 2>&1 | head -5

echo "=== STATUS ==="
python3 .agents/skills/build-cyberbench-task/scripts/workflow.py \
  --manifest tasksets/v3/incoming/generated/batch_1/001/.task-factory-runtime/task-factory.toml status 2>&1 | \
  python3 -c 'import sys,json; d=json.load(sys.stdin); print("phase:", d["phase"]); print("frozen:", d.get("frozen_hash") is not None); print("fairness:", (d.get("fairness") or {}).get("verdict","none")); print("disclosure:", (d.get("disclosure") or {}).get("verdict","none"))'
