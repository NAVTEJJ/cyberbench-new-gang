#!/bin/bash
export PATH="$HOME/.local/bin:$PATH"
REPO=/home/navtej/cyberbench
cd "$REPO"

echo "=== current state ==="
python3 -c "
import json
s = json.load(open('tasksets/v3/incoming/generated/batch_1/001/.task-factory-runtime/workflow/state.json'))
print('phase:', s['phase'])
print('trials:', len(s['jobs']['calibration']))
for j in s['jobs']['calibration']:
  for t in j['trials']:
    print(f\"  {t['trial']}: reward={t['reward']} solved={t['solved']} cost={t['cost_usd']}\")
print('spent:', s['spent_usd'])
print('budget:', s['budget_usd'])
print('remaining:', s['budget_usd'] - s['spent_usd'])
"

echo ""
echo "=== need 1 more trial? ==="
TOTAL=0
for j in $(python3 -c "import json; s=json.load(open('tasksets/v3/incoming/generated/batch_1/001/.task-factory-runtime/workflow/state.json')); [print(j) for j in s['jobs']['calibration']]"); do
  TOTAL=$((TOTAL + 1))
done
echo "completed calibration jobs: $TOTAL"
echo "qualification_trials config: $(python3 -c "import json; s=json.load(open('tasksets/v3/incoming/generated/batch_1/001/.task-factory-runtime/workflow/state.json')); print(len(s['jobs']['calibration']))")"