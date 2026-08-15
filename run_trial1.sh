#!/bin/bash
set -e
export PATH="$HOME/.local/bin:$PATH"
REPO=/home/navtej/cyberbench

cd "$REPO"
if [ -f .env ]; then set -a; . .env; set +a; fi

echo "=== RUN TARGET PROBE 1 ==="
python3 .agents/skills/build-cyberbench-task/scripts/workflow.py \
  --manifest tasksets/v3/incoming/generated/batch_1/001/.task-factory-runtime/task-factory.toml \
  run-target --attempts 1 2>&1 | python3 -c '
import sys,json
d=json.load(sys.stdin)
print("phase:", d.get("phase"))
print("completed:", d.get("completed_attempts"))
print("spent:", d.get("spent_usd"))
for j in d.get("jobs",[]):
  for t in j.get("trials",[]):
    print("  trial:", t.get("trial"), "reward:", t.get("reward"), "solved:", t.get("solved"), "exc:", (t.get("exception_info") or {}).get("exception_type","none"), "cost:", t.get("cost_usd"))
'

echo ""
echo "=== Inspect trial 1 trajectory ==="
JOB=$(ls -dt ${REPO}/tasksets/v3/incoming/generated/batch_1/001/.task-factory-runtime/jobs/*target_r* | head -1)
TRIAL=$(ls -d ${JOB}/ctr_relay_l0__* 2>/dev/null | head -1)
if [ -n "$TRIAL" ]; then
  echo "--- verifier details ---"
  cat "${TRIAL}/verifier/details.json" 2>&1
  echo ""
  echo "--- trajectory steps ---"
  python3 -c "
import json
t = json.load(open('${TRIAL}/agent/trajectory.json'))
steps = t.get('steps', t.get('messages', []))
print('total steps:', len(steps))
for i, s in enumerate(steps[:40]):
    tc = s.get('tool_calls', [])
    content = str(s.get('content', ''))[:150]
    print(f'  [{i}] {content}')
    for call in tc:
        name = call.get('function', {}).get('name', call.get('name', '?'))
        args = str(call.get('function', {}).get('arguments', call.get('arguments', '')))[:200]
        print(f'       tool: {name} args: {args}')
" 2>&1
fi
