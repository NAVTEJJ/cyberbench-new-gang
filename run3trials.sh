#!/bin/bash
set -e
export PATH="$HOME/.local/bin:$PATH"
REPO=/home/navtej/cyberbench
cd "$REPO"
if [ -f .env ]; then set -a; . .env; set +a; fi

echo "=== RUN TRIAL 1 ==="
python3 .agents/skills/build-cyberbench-task/scripts/workflow.py \
  --manifest tasksets/v3/incoming/generated/batch_1/001/.task-factory-runtime/task-factory.toml \
  run-target --attempts 1 2>&1 | python3 -c '
import sys, json
d = json.load(sys.stdin)
print("phase:", d.get("phase"), "spent:", d.get("spent_usd"))
for j in d.get("jobs", []):
    for t in j.get("trials", []):
        print("  trial:", t.get("trial"), "reward:", t.get("reward"), "solved:", t.get("solved"), "cost:", t.get("cost_usd"))
'

echo ""
echo "=== RUN TRIALS 2+3 ==="
python3 .agents/skills/build-cyberbench-task/scripts/workflow.py \
  --manifest tasksets/v3/incoming/generated/batch_1/001/.task-factory-runtime/task-factory.toml \
  run-target --attempts 2 2>&1 | python3 -c '
import sys, json
d = json.load(sys.stdin)
print("phase:", d.get("phase"), "spent:", d.get("spent_usd"))
for j in d.get("jobs", []):
    for t in j.get("trials", []):
        print("  trial:", t.get("trial"), "reward:", t.get("reward"), "solved:", t.get("solved"), "cost:", t.get("cost_usd"))
'

echo ""
echo "=== FINAL ==="
python3 -c '
import json
s = json.load(open("tasksets/v3/incoming/generated/batch_1/001/.task-factory-runtime/workflow/state.json"))
solved = sum(1 for j in s["jobs"]["calibration"] for t in j["trials"] if t["solved"])
total = sum(1 for j in s["jobs"]["calibration"] for t in j["trials"])
print("solved: %d/%d, spent: %s/%s, phase: %s" % (solved, total, s["spent_usd"], s["budget_usd"], s["phase"]))
'
