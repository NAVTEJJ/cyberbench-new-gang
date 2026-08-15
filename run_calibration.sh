#!/bin/bash
set -e
export PATH="$HOME/.local/bin:$PATH"
REPO=/home/navtej/cyberbench
SRC=/mnt/c/Users/NAVTEJ/Downloads/Cyber-Bench-main

# Sync updated files to WSL-native workspace.
cp "$SRC/tasksets/v3/incoming/generated/batch_1/001/ctr_relay_l0/environment/Dockerfile" \
   "$REPO/tasksets/v3/incoming/generated/batch_1/001/ctr_relay_l0/environment/Dockerfile"
cp "$SRC/tasksets/v3/incoming/generated/batch_1/001/ctr_relay_l0/environment/docker-compose.yaml" \
   "$REPO/tasksets/v3/incoming/generated/batch_1/001/ctr_relay_l0/environment/docker-compose.yaml"

# Copy review JSONs to WSL-native workflow dir.
cp "$SRC/tasksets/v3/incoming/generated/batch_1/001/.task-factory-runtime/workflow/fairness.json" \
   "$REPO/tasksets/v3/incoming/generated/batch_1/001/.task-factory-runtime/workflow/fairness.json" 2>/dev/null || true
cp "$SRC/tasksets/v3/incoming/generated/batch_1/001/.task-factory-runtime/workflow/disclosure.json" \
   "$REPO/tasksets/v3/incoming/generated/batch_1/001/.task-factory-runtime/workflow/disclosure.json" 2>/dev/null || true

cd "$REPO"
if [ -f .env ]; then set -a; . .env; set +a; fi

echo "=== VALIDATE ==="
python3 .agents/skills/build-cyberbench-task/scripts/workflow.py \
  --manifest tasksets/v3/incoming/generated/batch_1/001/.task-factory-runtime/task-factory.toml validate 2>&1 | \
  python3 -c 'import sys,json; d=json.load(sys.stdin); print("passed:",d["passed"]); [print(" ",c["name"],c["passed"]) for c in d["checks"]]'

echo "=== ORACLE ==="
python3 .agents/skills/build-cyberbench-task/scripts/workflow.py \
  --manifest tasksets/v3/incoming/generated/batch_1/001/.task-factory-runtime/task-factory.toml oracle 2>&1 | \
  python3 -c 'import sys,json; d=json.load(sys.stdin); t=d["trials"][0]; print("reward:",t.get("reward"),"solved:",t.get("solved"),"exc:",(t.get("exception_info") or {}).get("exception_type","none"))'

echo "=== RECORD FAIRNESS ==="
python3 .agents/skills/build-cyberbench-task/scripts/workflow.py \
  --manifest tasksets/v3/incoming/generated/batch_1/001/.task-factory-runtime/task-factory.toml \
  record-fairness --file tasksets/v3/incoming/generated/batch_1/001/.task-factory-runtime/workflow/fairness.json 2>&1 | \
  python3 -c 'import sys,json; d=json.load(sys.stdin); print("verdict:",d.get("verdict"))'

echo "=== RECORD DISCLOSURE ==="
python3 .agents/skills/build-cyberbench-task/scripts/workflow.py \
  --manifest tasksets/v3/incoming/generated/batch_1/001/.task-factory-runtime/task-factory.toml \
  record-disclosure --file tasksets/v3/incoming/generated/batch_1/001/.task-factory-runtime/workflow/disclosure.json \
  --reviewer-kind isolated_agent 2>&1 | \
  python3 -c 'import sys,json; d=json.load(sys.stdin); print("verdict:",d.get("verdict"))'

echo "=== RUN TARGET PROBE (1 trial) ==="
python3 .agents/skills/build-cyberbench-task/scripts/workflow.py \
  --manifest tasksets/v3/incoming/generated/batch_1/001/.task-factory-runtime/task-factory.toml \
  run-target --attempts 1 2>&1 | \
  python3 -c '
import sys,json
d=json.load(sys.stdin)
print("phase:", d.get("phase"))
print("completed:", d.get("completed_attempts"))
print("spent:", d.get("spent_usd"))
for j in d.get("jobs",[]):
  for t in j.get("trials",[]):
    print("  trial:", t.get("trial"), "reward:", t.get("reward"), "solved:", t.get("solved"), "exc:", (t.get("exception_info") or {}).get("exception_type","none"), "cost:", t.get("cost_usd"))
'
