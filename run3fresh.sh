#!/bin/bash
set -e
export PATH="$HOME/.local/bin:$PATH"
cd /home/navtej/cyberbench

# Clear calibration jobs (the Docker failure left an empty one).
python3 -c '
import json
state_path = "tasksets/v3/incoming/generated/batch_1/001/.task-factory-runtime/workflow/state.json"
s = json.load(open(state_path))
s["jobs"]["calibration"] = []
s["analysis"] = None
with open(state_path, "w") as f:
    json.dump(s, f, indent=2, sort_keys=True)
print("calibration cleared")
'

if [ -f .env ]; then set -a; . .env; set +a; fi

echo "=== RUN 3 TRIALS ==="
for i in 1 2 3; do
  echo "--- trial $i ---"
  python3 .agents/skills/build-cyberbench-task/scripts/workflow.py \
    --manifest tasksets/v3/incoming/generated/batch_1/001/.task-factory-runtime/task-factory.toml \
    run-target --attempts 1 2>&1 | tail -5
  echo ""
done

echo "=== FINAL ==="
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
