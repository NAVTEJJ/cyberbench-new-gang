#!/bin/bash
set -e
export PATH="$HOME/.local/bin:$PATH"
REPO=/home/navtej/cyberbench
cd "$REPO"
if [ -f .env ]; then set -a; . .env; set +a; fi

echo "=== RECORD FAIRNESS ==="
sed -i '1s/^\xEF\xBB\xBF//' "$REPO/tasksets/v3/incoming/generated/batch_1/001/.task-factory-runtime/workflow/fairness.json"
python3 .agents/skills/build-cyberbench-task/scripts/workflow.py \
  --manifest tasksets/v3/incoming/generated/batch_1/001/.task-factory-runtime/task-factory.toml \
  record-fairness --file tasksets/v3/incoming/generated/batch_1/001/.task-factory-runtime/workflow/fairness.json 2>&1 | \
  python3 -c 'import sys,json; d=json.load(sys.stdin); print("verdict:",d.get("verdict"))'

echo "=== RECORD DISCLOSURE ==="
sed -i '1s/^\xEF\xBB\xBF//' "$REPO/tasksets/v3/incoming/generated/batch_1/001/.task-factory-runtime/workflow/disclosure.json"
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
  run-target --attempts 1 2>&1 | python3 -c '
import sys,json
d=json.load(sys.stdin)
print("phase:", d.get("phase"), "spent:", d.get("spent_usd"))
for j in d.get("jobs",[]):
  for t in j.get("trials",[]):
    print(f"  {t[\"trial\"]}: reward={t[\"reward\"]} solved={t[\"solved\"]} cost={t[\"cost_usd\"]}")
'

echo ""
echo "=== RUN TRIALS 2+3 ==="
python3 .agents/skills/build-cyberbench-task/scripts/workflow.py \
  --manifest tasksets/v3/incoming/generated/batch_1/001/.task-factory-runtime/task-factory.toml \
  run-target --attempts 2 2>&1 | python3 -c '
import sys,json
d=json.load(sys.stdin)
print("phase:", d.get("phase"), "spent:", d.get("spent_usd"))
for j in d.get("jobs",[]):
  for t in j.get("trials",[]):
    print(f"  {t[\"trial\"]}: reward={t[\"reward\"]} solved={t[\"solved\"]} cost={t[\"cost_usd\"]}")
'

echo ""
echo "=== FINAL STATE ==="
python3 -c "
import json
s = json.load(open('tasksets/v3/incoming/generated/batch_1/001/.task-factory-runtime/workflow/state.json'))
print('phase:', s['phase'])
print('spent:', s['spent_usd'], '/', s['budget_usd'])
solved = 0
for j in s['jobs']['calibration']:
  for t in j['trials']:
    print(f\"  {t['trial']}: reward={t['reward']} solved={t['solved']} cost={t['cost_usd']}\")
    if t['solved']: solved += 1
print(f'total solved: {solved}/3')
"