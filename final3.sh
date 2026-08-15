#!/bin/bash
set -e
export PATH="$HOME/.local/bin:$PATH"
REPO=/home/navtej/cyberbench
SRC=/mnt/c/Users/NAVTEJ/Downloads/Cyber-Bench-main

# Copy and clean review JSONs.
for f in fairness.json disclosure.json; do
  cp "$SRC/tasksets/v3/incoming/generated/batch_1/001/.task-factory-runtime/workflow/$f" \
     "$REPO/tasksets/v3/incoming/generated/batch_1/001/.task-factory-runtime/workflow/$f"
  sed -i '1s/^\xEF\xBB\xBF//' "$REPO/tasksets/v3/incoming/generated/batch_1/001/.task-factory-runtime/workflow/$f"
done

cd "$REPO"
if [ -f .env ]; then set -a; . .env; set +a; fi

echo "=== RECORD FAIRNESS ==="
python3 .agents/skills/build-cyberbench-task/scripts/workflow.py \
  --manifest tasksets/v3/incoming/generated/batch_1/001/.task-factory-runtime/task-factory.toml \
  record-fairness --file tasksets/v3/incoming/generated/batch_1/001/.task-factory-runtime/workflow/fairness.json 2>&1 | \
  python3 -c 'import sys,json; d=json.load(sys.stdin); print("verdict:",d.get("verdict"))'

echo "=== RECORD DISCLOSURE ==="
python3 .agents/skills/build-cyberbench-task/scripts/workflow.py \
  --manifest tasksets/v3/incoming/generated/batch_1/001/.task-factory-runtime/task-factory.toml \
  record-disclosure --file tasksets/v3/incoming/generated/batch_1/001/.task-factory-runtime/workflow/disclosure.json \
  --reviewer-kind isolated_agent 2>&1 | \
  python3 -c 'import sys,json; d=json.load(sys.stdin); print("verdict:",d.get("verdict"))'

echo "=== STATUS ==="
python3 .agents/skills/build-cyberbench-task/scripts/workflow.py \
  --manifest tasksets/v3/incoming/generated/batch_1/001/.task-factory-runtime/task-factory.toml status 2>&1 | \
  python3 -c 'import sys,json; d=json.load(sys.stdin); print("phase:",d["phase"],"frozen:",d.get("frozen_hash") is not None,"trials:",len(d["jobs"]["calibration"]),"spent:",d["spent_usd"])'

echo ""
echo "=== RUN TRIAL 1 ==="
python3 .agents/skills/build-cyberbench-task/scripts/workflow.py \
  --manifest tasksets/v3/incoming/generated/batch_1/001/.task-factory-runtime/task-factory.toml \
  run-target --attempts 1 2>&1 | tail -15

echo ""
echo "=== RUN TRIAL 2 ==="
python3 .agents/skills/build-cyberbench-task/scripts/workflow.py \
  --manifest tasksets/v3/incoming/generated/batch_1/001/.task-factory-runtime/task-factory.toml \
  run-target --attempts 1 2>&1 | tail -15

echo ""
echo "=== RUN TRIAL 3 ==="
python3 .agents/skills/build-cyberbench-task/scripts/workflow.py \
  --manifest tasksets/v3/incoming/generated/batch_1/001/.task-factory-runtime/task-factory.toml \
  run-target --attempts 1 2>&1 | tail -15

echo ""
echo "=== FINAL STATE ==="
python3 -c '
import json
s = json.load(open("tasksets/v3/incoming/generated/batch_1/001/.task-factory-runtime/workflow/state.json"))
solved = sum(1 for j in s["jobs"]["calibration"] for t in j["trials"] if t["solved"])
total = sum(1 for j in s["jobs"]["calibration"] for t in j["trials"])
print("solved: %d/%d, spent: %s/%s, phase: %s" % (solved, total, s["spent_usd"], s["budget_usd"], s["phase"]))
for j in s["jobs"]["calibration"]:
    for t in j["trials"]:
        print("  %s: reward=%s solved=%s cost=%s" % (t["trial"], t["reward"], t["solved"], t["cost_usd"]))
'
