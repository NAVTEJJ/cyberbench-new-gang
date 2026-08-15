#!/bin/bash
export PATH="$HOME/.local/bin:$PATH"
cd /mnt/c/Users/NAVTEJ/Downloads/Cyber-Bench-main

echo "=== check latest oracle trial ==="
JOB_DIR=$(ls -d .task-factory-runtime/jobs/*oracle_r5* 2>/dev/null | head -1)
echo "job: $JOB_DIR"
TRIAL=$(ls -d "$JOB_DIR"/ctr_relay_l0__* 2>/dev/null | head -1)
echo "trial: $TRIAL"
echo "=== result.json ==="
cat "$TRIAL/result.json" 2>&1 | python3 -c "import sys,json; d=json.load(sys.stdin); print('reward:', d.get('verifier_result',{}).get('rewards',{})); print('exception:', d.get('exception_info',{}).get('exception_type','none')); print('agent_result:', d.get('agent_result',{}).get('result','none'))" 2>&1
echo "=== verifier files ==="
ls -la "$TRIAL/verifier/" 2>&1
echo "=== flags.txt ==="
cat "$TRIAL/artifacts/app/flags.txt" 2>&1 || echo "no flags.txt"
echo "=== trial.log (last 20) ==="
tail -20 "$TRIAL/trial.log" 2>&1
echo "=== solve output ==="
cat "$TRIAL/artifacts/logs/agent/stdout.txt" 2>&1 | tail -10 || echo "no stdout"
