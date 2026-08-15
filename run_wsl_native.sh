#!/bin/bash
set -e
export PATH="$HOME/.local/bin:$PATH"
REPO=/home/navtej/cyberbench

# Sync the updated compose file to WSL-native workspace.
cp /mnt/c/Users/NAVTEJ/Downloads/Cyber-Bench-main/tasksets/v3/incoming/generated/batch_1/001/ctr_relay_l0/environment/docker-compose.yaml \
   "$REPO/tasksets/v3/incoming/generated/batch_1/001/ctr_relay_l0/environment/docker-compose.yaml"

cd "$REPO"
if [ -f .env ]; then set -a; . .env; set +a; fi

echo "=== VALIDATE ==="
python3 .agents/skills/build-cyberbench-task/scripts/workflow.py \
  --manifest tasksets/v3/incoming/generated/batch_1/001/.task-factory-runtime/task-factory.toml validate 2>&1 | \
  python3 -c 'import sys,json; d=json.load(sys.stdin); print("passed:",d["passed"]); [print(" ",c["name"],c["passed"]) for c in d["checks"]]'

echo "=== ORACLE ==="
python3 .agents/skills/build-cyberbench-task/scripts/workflow.py \
  --manifest tasksets/v3/incoming/generated/batch_1/001/.task-factory-runtime/task-factory.toml oracle 2>&1 | \
  python3 -c '
import sys,json
d=json.load(sys.stdin)
t=d.get("trials",[{}])[0]
print("reward:", t.get("reward"))
print("solved:", t.get("solved"))
print("exception:", (t.get("exception_info") or {}).get("exception_type","none"))
cmd=d.get("command",{})
print("returncode:", cmd.get("returncode"))
'

echo "=== oracle.txt ==="
JOB=$(ls -d $REPO/tasksets/v3/incoming/generated/batch_1/001/.task-factory-runtime/jobs/*oracle* 2>/dev/null | tail -1)
TRIAL=$(ls -d ${JOB}/ctr_relay_l0__* 2>/dev/null | head -1)
cat "${TRIAL}/agent/oracle.txt" 2>&1 | tail -5
echo "=== exit-code ==="
cat "${TRIAL}/agent/exit-code.txt" 2>&1
echo "=== verifier details ==="
cat "${TRIAL}/verifier/details.json" 2>&1
