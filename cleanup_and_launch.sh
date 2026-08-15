#!/bin/bash
export PATH="$HOME/.local/bin:$PATH"

echo "=== stopping all leftover containers ==="
docker ps --format "{{.Names}}" | grep "ctr_relay_l0" | xargs -r docker stop 2>/dev/null
docker ps --format "{{.Names}}" | grep "ctr_relay_l0" | xargs -r docker rm -f 2>/dev/null
echo "cleanup done"

echo "=== clearing calibration state ==="
cd /home/navtej/cyberbench
python3 -c '
import json
state_path = "tasksets/v3/incoming/generated/batch_1/001/.task-factory-runtime/workflow/state.json"
s = json.load(open(state_path))
s["jobs"]["calibration"] = []
s["analysis"] = None
with open(state_path, "w") as f:
    json.dump(s, f, indent=2, sort_keys=True)
print("cleared")
'

echo "=== launching 3 trials in background ==="
if [ -f .env ]; then set -a; . .env; set +a; fi

nohup python3 .agents/skills/build-cyberbench-task/scripts/workflow.py \
  --manifest tasksets/v3/incoming/generated/batch_1/001/.task-factory-runtime/task-factory.toml \
  run-target --attempts 1 > /tmp/trial1.log 2>&1 &
echo "trial 1 PID: $!"

echo "Done. Trials will run in background. Check back with:"
echo "  cat /tmp/trial1.log"
echo "  python3 -c 'import json; s=json.load(open(\"tasksets/v3/incoming/generated/batch_1/001/.task-factory-runtime/workflow/state.json\")); print(len(s[\"jobs\"][\"calibration\"]), \"trials\")'"
