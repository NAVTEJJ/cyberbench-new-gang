#!/bin/bash
set -e
export PATH="$HOME/.local/bin:$PATH"
REPO=/home/navtej/cyberbench
SRC=/mnt/c/Users/NAVTEJ/Downloads/Cyber-Bench-main

# Sync all updated files.
cp "$SRC/tasksets/v3/incoming/generated/batch_1/001/ctr_relay_l0/environment/assets/ctr-relay/app.py" \
   "$REPO/tasksets/v3/incoming/generated/batch_1/001/ctr_relay_l0/environment/assets/ctr-relay/app.py"
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
echo "=== RUN PROBE 1 ==="
python3 .agents/skills/build-cyberbench-task/scripts/workflow.py \
  --manifest tasksets/v3/incoming/generated/batch_1/001/.task-factory-runtime/task-factory.toml \
  run-target --attempts 1 2>&1 | python3 -c '
import sys,json
d=json.load(sys.stdin)
print("phase:", d.get("phase"), "spent:", d.get("spent_usd"))
for j in d.get("jobs",[]):
  for t in j.get("trials",[]):
    print("  trial:", t.get("trial"), "reward:", t.get("reward"), "solved:", t.get("solved"), "exc:", (t.get("exception_info") or {}).get("exception_type","none"), "cost:", t.get("cost_usd"))
'

echo ""
echo "=== Inspect probe ==="
JOB=$(ls -dt ${REPO}/tasksets/v3/incoming/generated/batch_1/001/.task-factory-runtime/jobs/*target_r* | head -1)
TRIAL=$(ls -d ${JOB}/ctr_relay_l0__* 2>/dev/null | head -1)
cat "${TRIAL}/verifier/details.json" 2>&1
echo ""
python3 -c "
import json
t = json.load(open('${TRIAL}/agent/trajectory.json'))
steps = t.get('steps', t.get('messages', []))
print('total steps:', len(steps))
for i, s in enumerate(steps[:25]):
    tc = s.get('tool_calls', [])
    content = str(s.get('content', ''))[:150]
    print(f'  [{i}] {content}')
    for call in tc:
        args = str(call.get('function', {}).get('arguments', call.get('arguments', '')))[:250]
        print(f'       -> {args}')
" 2>&1
