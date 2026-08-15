#!/bin/bash
export PATH="$HOME/.local/bin:$PATH"
REPO=/home/navtej/cyberbench
JOB=$(ls -dt ${REPO}/tasksets/v3/incoming/generated/batch_1/001/.task-factory-runtime/jobs/*target_r3* | head -1)
TRIAL="${JOB}/ctr_relay_l0__x2r9ytS"

echo "=== verifier details ==="
cat "${TRIAL}/verifier/details.json" 2>&1

echo ""
echo "=== trajectory (tool calls summary) ==="
python3 -c "
import json
t = json.load(open('${TRIAL}/agent/trajectory.json'))
steps = t.get('steps', t.get('messages', []))
print('total steps:', len(steps))
for i, s in enumerate(steps[:30]):
    role = s.get('role', s.get('type', '?'))
    tc = s.get('tool_calls', [])
    content = str(s.get('content', ''))[:200]
    print(f'  [{i}] {role}: {content}')
    for call in tc:
        name = call.get('function', {}).get('name', call.get('name', '?'))
        args = str(call.get('function', {}).get('arguments', call.get('arguments', '')))[:300]
        print(f'       tool: {name} args: {args}')
" 2>&1

echo ""
echo "=== agent command logs ==="
find "${TRIAL}/agent" -name "command-*" -type d | sort | while read d; do
  echo "--- $d ---"
  cat "$d/command.txt" 2>&1
  echo "--- stdout (first 500) ---"
  head -c 500 "$d/stdout.txt" 2>&1
  echo ""
done 2>&1 | head -80

echo ""
echo "=== oracle.txt equivalent (agent output) ==="
find "${TRIAL}/agent" -name "*.txt" -exec echo "--- {} ---" \; -exec head -20 {} \; 2>&1 | head -60
