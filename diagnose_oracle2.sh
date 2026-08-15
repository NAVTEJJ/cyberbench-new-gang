#!/bin/bash
export PATH="$HOME/.local/bin:$PATH"
TRIAL="/home/navtej/cyberbench/tasksets/v3/incoming/generated/batch_1/001/.task-factory-runtime/jobs/generated_batch_1_001_oracle_r1_20260809_173101_331146/ctr_relay_l0__gXtht47"

echo "=== FULL trial.log ==="
cat "${TRIAL}/trial.log" 2>&1

echo ""
echo "=== FULL result.json ==="
python3 -c "
import json
d = json.load(open('${TRIAL}/result.json'))
print(json.dumps(d, indent=2))
" 2>&1

echo ""
echo "=== artifact manifest ==="
cat "${TRIAL}/artifacts/manifest.json" 2>&1

echo ""
echo "=== solve.sh permissions ==="
ls -la /home/navtej/cyberbench/tasksets/v3/incoming/generated/batch_1/001/ctr_relay_l0/solution/solve.sh 2>&1
