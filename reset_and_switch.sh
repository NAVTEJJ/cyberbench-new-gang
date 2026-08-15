#!/bin/bash
set -e
export PATH="$HOME/.local/bin:$PATH"
REPO=/home/navtej/cyberbench
SRC=/mnt/c/Users/NAVTEJ/Downloads/Cyber-Bench-main

# Sync updated manifest.
cp "$SRC/tasksets/v3/incoming/generated/batch_1/001/.task-factory-runtime/task-factory.toml" \
   "$REPO/tasksets/v3/incoming/generated/batch_1/001/.task-factory-runtime/task-factory.toml"

cd "$REPO"

echo "=== current state before reset ==="
python3 -c "
import json
s = json.load(open('tasksets/v3/incoming/generated/batch_1/001/.task-factory-runtime/workflow/state.json'))
print('phase:', s['phase'])
print('calibration jobs:', len(s['jobs']['calibration']))
print('oracle jobs:', len(s['jobs']['oracle']))
print('spent:', s['spent_usd'])
print('charges:', len(s['charges']))
print('fairness:', (s.get('fairness') or {}).get('verdict','none'))
print('disclosure:', (s.get('disclosure') or {}).get('verdict','none'))
print('frozen:', s.get('frozen_hash') is not None)
"

echo ""
echo "=== surgically reset calibration state ==="
python3 -c "
import json
state_path = 'tasksets/v3/incoming/generated/batch_1/001/.task-factory-runtime/workflow/state.json'
s = json.load(open(state_path))
# Clear calibration jobs and charges, keep oracle/fairness/disclosure.
s['jobs']['calibration'] = []
s['charges'] = []
s['spent_usd'] = 0.0
s['analysis'] = None
s['qualification'] = None
s['phase'] = 'ACTIVE'
s['last_error'] = None
with open(state_path, 'w') as f:
    json.dump(s, f, indent=2, sort_keys=True)
print('reset done')
"

echo ""
echo "=== dry-run (confirms target model) ==="
python3 .agents/skills/build-cyberbench-task/scripts/workflow.py \
  --manifest tasksets/v3/incoming/generated/batch_1/001/.task-factory-runtime/task-factory.toml dry-run 2>&1 | \
  python3 -c 'import sys,json; d=json.load(sys.stdin); print("target_model:", d["target_model"]); print("budget:", d["target_run_budget_usd"])'

echo ""
echo "=== status after reset ==="
python3 .agents/skills/build-cyberbench-task/scripts/workflow.py \
  --manifest tasksets/v3/incoming/generated/batch_1/001/.task-factory-runtime/task-factory.toml status 2>&1 | \
  python3 -c '
import sys,json
d=json.load(sys.stdin)
print("phase:", d["phase"])
print("fairness:", (d.get("fairness") or {}).get("verdict","none"))
print("disclosure:", (d.get("disclosure") or {}).get("verdict","none"))
print("frozen:", d.get("frozen_hash") is not None)
print("calibration trials:", len(d["jobs"]["calibration"]))
print("oracle trials:", len(d["jobs"]["oracle"]))
print("spent:", d["spent_usd"])
'
