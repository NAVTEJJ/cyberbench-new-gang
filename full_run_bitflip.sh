#!/bin/bash
set -e
export PATH="$HOME/.local/bin:$PATH"
REPO=/home/navtej/cyberbench
SRC=/mnt/c/Users/NAVTEJ/Downloads/Cyber-Bench-main

# Full sync of all task files.
rsync -av --delete --exclude='__pycache__' "$SRC/tasksets/v3/incoming/generated/batch_1/001/ctr_relay_l0/" \
  "$REPO/tasksets/v3/incoming/generated/batch_1/001/ctr_relay_l0/"

# Copy analysis.
cp "$SRC/tasksets/v3/incoming/generated/batch_1/001/.task-factory-runtime/workflow/analysis.json" \
   "$REPO/tasksets/v3/incoming/generated/batch_1/001/.task-factory-runtime/workflow/analysis.json"
sed -i '1s/^\xEF\xBB\xBF//' "$REPO/tasksets/v3/incoming/generated/batch_1/001/.task-factory-runtime/workflow/analysis.json"

cd "$REPO"
if [ -f .env ]; then set -a; . .env; set +a; fi

echo "=== RECORD ANALYSIS ==="
python3 .agents/skills/build-cyberbench-task/scripts/workflow.py \
  --manifest tasksets/v3/incoming/generated/batch_1/001/.task-factory-runtime/task-factory.toml \
  record-analysis --file tasksets/v3/incoming/generated/batch_1/001/.task-factory-runtime/workflow/analysis.json 2>&1 | \
  python3 -c 'import sys,json; d=json.load(sys.stdin); print("classification:",d.get("overall_classification"))'

echo "=== VALIDATE ==="
python3 .agents/skills/build-cyberbench-task/scripts/workflow.py \
  --manifest tasksets/v3/incoming/generated/batch_1/001/.task-factory-runtime/task-factory.toml validate 2>&1 | \
  python3 -c 'import sys,json; d=json.load(sys.stdin); print("passed:",d["passed"]); [print(" ",c["name"],c["passed"]) for c in d["checks"]]'

echo "=== ORACLE ==="
python3 .agents/skills/build-cyberbench-task/scripts/workflow.py \
  --manifest tasksets/v3/incoming/generated/batch_1/001/.task-factory-runtime/task-factory.toml oracle 2>&1 | \
  python3 -c 'import sys,json; d=json.load(sys.stdin); t=d["trials"][0]; print("reward:",t.get("reward"),"solved:",t.get("solved"),"exc:",(t.get("exception_info") or {}).get("exception_type","none"))'

# Quick fairness + disclosure check (reuse existing reviews — they judge the package not the vuln class).
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
echo "=== RUN ALL 3 TRIALS ==="
python3 .agents/skills/build-cyberbench-task/scripts/workflow.py \
  --manifest tasksets/v3/incoming/generated/batch_1/001/.task-factory-runtime/task-factory.toml \
  run-target --attempts 1 2>&1 | python3 -c '
import sys,json; d=json.load(sys.stdin); print("trial 1:", [(t["trial"],t["reward"],t["solved"],t["cost_usd"]) for j in d["jobs"] for t in j["trials"]])
'
echo ""
python3 .agents/skills/build-cyberbench-task/scripts/workflow.py \
  --manifest tasksets/v3/incoming/generated/batch_1/001/.task-factory-runtime/task-factory.toml \
  run-target --attempts 2 2>&1 | python3 -c '
import sys,json; d=json.load(sys.stdin); print("trials 2-3:", [(t["trial"],t["reward"],t["solved"],t["cost_usd"]) for j in d["jobs"] for t in j["trials"]])
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