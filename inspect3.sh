#!/bin/bash
export PATH="$HOME/.local/bin:$PATH"
REPO=/home/navtej/cyberbench

# Get the 3 latest target trials.
echo "=== 3 trial trajectories ==="
for JOB in $(ls -dt ${REPO}/tasksets/v3/incoming/generated/batch_1/001/.task-factory-runtime/jobs/*target_r* | head -3); do
  TRIAL=$(ls -d ${JOB}/ctr_relay_l0__* 2>/dev/null | head -1)
  echo "--- $(basename $TRIAL) ---"
  cat "${TRIAL}/verifier/details.json" 2>&1 | python3 -c 'import sys,json; d=json.load(sys.stdin); print("reward:",d["reward"],"flags:",d.get("submitted_flags",[]))' 2>&1
  python3 -c "
import json
t = json.load(open('${TRIAL}/agent/trajectory.json'))
steps = t.get('steps', t.get('messages', []))
for i, s in enumerate(steps[:15]):
    tc = s.get('tool_calls', [])
    content = str(s.get('content', ''))[:120]
    print(f'  [{i}] {content}')
    for call in tc:
        args = str(call.get('function', {}).get('arguments', call.get('arguments', '')))[:200]
        print(f'       -> {args}')
" 2>&1
  echo ""
done
