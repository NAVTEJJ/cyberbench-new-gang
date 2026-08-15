#!/bin/bash
export PATH="$HOME/.local/bin:$PATH"
REPO=/home/navtej/cyberbench
JOB=$(ls -dt ${REPO}/tasksets/v3/incoming/generated/batch_1/001/.task-factory-runtime/jobs/*target_r* | head -1)
TRIAL=$(ls -d ${JOB}/ctr_relay_l0__* 2>/dev/null | head -1)
echo "=== verifier ==="
cat "${TRIAL}/verifier/details.json" 2>&1
echo ""
echo "=== trajectory ==="
python3 -c "
import json
t = json.load(open('${TRIAL}/agent/trajectory.json'))
steps = t.get('steps', t.get('messages', []))
print('total steps:', len(steps))
for i, s in enumerate(steps[:30]):
    tc = s.get('tool_calls', [])
    content = str(s.get('content', ''))[:200]
    print(f'  [{i}] {content}')
    for call in tc:
        args = str(call.get('function', {}).get('arguments', call.get('arguments', '')))[:300]
        print(f'       -> {args}')
" 2>&1
