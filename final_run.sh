#!/bin/bash
set -e
export PATH="$HOME/.local/bin:$PATH"
REPO=/home/navtej/cyberbench
SRC=/mnt/c/Users/NAVTEJ/Downloads/Cyber-Bench-main

# Full sync.
rsync -av --delete --exclude='__pycache__' "$SRC/tasksets/v3/incoming/generated/batch_1/001/ctr_relay_l0/" \
  "$REPO/tasksets/v3/incoming/generated/batch_1/001/ctr_relay_l0/"

# Copy and clean review JSONs.
for f in fairness.json disclosure.json; do
  cp "$SRC/tasksets/v3/incoming/generated/batch_1/001/.task-factory-runtime/workflow/$f" \
     "$REPO/tasksets/v3/incoming/generated/batch_1/001/.task-factory-runtime/workflow/$f"
  sed -i '1s/^\xEF\xBB\xBF//' "$REPO/tasksets/v3/incoming/generated/batch_1/001/.task-factory-runtime/workflow/$f"
done

cd "$REPO"
if [ -f .env ]; then set -a; . .env; set +a; fi

echo "=== VALIDATE ==="
python3 .agents/skills/build-cyberbench-task/scripts/workflow.py \
  --manifest tasksets/v3/incoming/generated/batch_1/001/.task-factory-runtime/task-factory.toml validate 2>&1 | \
  python3 -c 'import sys,json; d=json.load(sys.stdin); print("passed:",d["passed"]); [print(" ",c["name"],c["passed"]) for c in d["checks"]]'

echo "=== ORACLE ==="
python3 .agents/skills/build-cyberbench-task/scripts/workflow.py \
  --manifest tasksets/v3/incoming/generated/batch_1/001/.task-factory-runtime/task-factory.toml oracle 2>&1 | \
  python3 -c 'import sys,json; d=json.load(sys.stdin); t=d["trials"][0]; print("reward:",t.get("reward"),"solved:",t.get("solved"),"exc:",(t.get("exception_info") or {}).get("exception_type","none"))'

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
echo "=== FINAL ==="
python3 -c "
import json
s = json.load(open('tasksets/v3/incoming/generated/batch_1/001/.task-factory-runtime/workflow/state.json'))
solved = sum(1 for j in s['jobs']['calibration'] for t in j['trials'] if t['solved'])
total = sum(1 for j in s['jobs']['calibration'] for t in j['trials'])
print(f'solved: {solved}/{total}, spent: {s[\"spent_usd\"]}/{s[\"budget_usd\"]}, phase: {s[\"phase\"]}')
"