#!/bin/bash
export PATH="$HOME/.local/bin:$PATH"
REPO=/home/navtej/cyberbench

JOB_DIR=$(ls -d ${REPO}/tasksets/v3/incoming/generated/batch_1/001/.task-factory-runtime/jobs/*oracle_r1* 2>/dev/null | head -1)
echo "job: $JOB_DIR"
TRIAL=$(ls -d ${JOB_DIR}/ctr_relay_l0__* 2>/dev/null | head -1)
echo "trial: $TRIAL"

if [ -z "$TRIAL" ]; then
  echo "NO TRIAL FOUND - listing jobs dir:"
  ls -la ${REPO}/tasksets/v3/incoming/generated/batch_1/001/.task-factory-runtime/jobs/ 2>&1
  exit 1
fi

echo "=== verifier details.json ==="
cat "${TRIAL}/verifier/details.json" 2>&1
echo ""
echo "=== result.json (key fields) ==="
python3 -c "
import json
d = json.load(open('${TRIAL}/result.json'))
vr = d.get('verifier_result', {})
ar = d.get('agent_result', {})
print('reward:', vr.get('rewards'))
print('agent returncode:', ar.get('returncode'))
print('agent stdout:', (ar.get('stdout','') or '')[:1000])
print('agent stderr:', (ar.get('stderr','') or '')[:1000])
print('exception:', d.get('exception_info'))
" 2>&1

echo "=== artifacts listing ==="
find "${TRIAL}/artifacts" -type f 2>&1 | head -30

echo "=== flags.txt ==="
find "${TRIAL}" -name "flags.txt" -exec cat {} \; 2>&1 || echo "no flags.txt found"

echo "=== trial.log (last 30) ==="
tail -30 "${TRIAL}/trial.log" 2>&1
