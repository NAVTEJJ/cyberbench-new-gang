#!/bin/bash
set -e
export PATH="$HOME/.local/bin:$PATH"
REPO=/home/navtej/cyberbench
SRC=/mnt/c/Users/NAVTEJ/Downloads/Cyber-Bench-main

cp "$SRC/tasksets/v3/incoming/generated/batch_1/001/.task-factory-runtime/workflow/analysis.json" \
   "$REPO/tasksets/v3/incoming/generated/batch_1/001/.task-factory-runtime/workflow/analysis.json"
sed -i '1s/^\xEF\xBB\xBF//' "$REPO/tasksets/v3/incoming/generated/batch_1/001/.task-factory-runtime/workflow/analysis.json"

cd "$REPO"
if [ -f .env ]; then set -a; . .env; set +a; fi

echo "=== RECORD ANALYSIS ==="
python3 .agents/skills/build-cyberbench-task/scripts/workflow.py \
  --manifest tasksets/v3/incoming/generated/batch_1/001/.task-factory-runtime/task-factory.toml \
  record-analysis --file tasksets/v3/incoming/generated/batch_1/001/.task-factory-runtime/workflow/analysis.json 2>&1 | head -5

echo "=== RUN TRIALS 2+3 ==="
python3 .agents/skills/build-cyberbench-task/scripts/workflow.py \
  --manifest tasksets/v3/incoming/generated/batch_1/001/.task-factory-runtime/task-factory.toml \
  run-target --attempts 2 2>&1 | tail -20

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
