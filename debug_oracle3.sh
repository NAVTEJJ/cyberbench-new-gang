#!/bin/bash
export PATH="$HOME/.local/bin:$PATH"
REPO=/home/navtej/cyberbench
JOB=$(ls -dt ${REPO}/tasksets/v3/incoming/generated/batch_1/001/.task-factory-runtime/jobs/*oracle* 2>/dev/null | head -1)
TRIAL=$(ls -d ${JOB}/ctr_relay_l0__* 2>/dev/null | head -1)
echo "trial: $TRIAL"
echo "=== oracle.txt ==="
cat "${TRIAL}/agent/oracle.txt" 2>&1
echo "=== exit-code ==="
cat "${TRIAL}/agent/exit-code.txt" 2>&1
echo "=== verifier ==="
cat "${TRIAL}/verifier/details.json" 2>&1
echo "=== result.json (exc) ==="
python3 -c "import json; d=json.load(open('${TRIAL}/result.json')); print('exc:', d.get('exception_info',{}).get('exception_type','none'))" 2>&1