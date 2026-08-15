#!/bin/bash
set -e
export PATH="$HOME/.local/bin:$PATH"
REPO=/home/navtej/cyberbench
SRC=/mnt/c/Users/NAVTEJ/Downloads/Cyber-Bench-main

# Sync all updated task files to WSL-native workspace.
for f in Dockerfile docker-compose.yaml; do
  cp "$SRC/tasksets/v3/incoming/generated/batch_1/001/ctr_relay_l0/environment/$f" \
     "$REPO/tasksets/v3/incoming/generated/batch_1/001/ctr_relay_l0/environment/$f"
done
for f in task.toml instruction.md; do
  cp "$SRC/tasksets/v3/incoming/generated/batch_1/001/ctr_relay_l0/$f" \
     "$REPO/tasksets/v3/incoming/generated/batch_1/001/ctr_relay_l0/$f"
done
cp "$SRC/tasksets/v3/incoming/generated/batch_1/001/.task-factory-runtime/task-factory.toml" \
   "$REPO/tasksets/v3/incoming/generated/batch_1/001/.task-factory-runtime/task-factory.toml"

# Copy analysis JSON (strip BOM).
cp "$SRC/tasksets/v3/incoming/generated/batch_1/001/.task-factory-runtime/workflow/analysis.json" \
   "$REPO/tasksets/v3/incoming/generated/batch_1/001/.task-factory-runtime/workflow/analysis.json"
sed -i '1s/^\xEF\xBB\xBF//' "$REPO/tasksets/v3/incoming/generated/batch_1/001/.task-factory-runtime/workflow/analysis.json"

cd "$REPO"
if [ -f .env ]; then set -a; . .env; set +a; fi

echo "=== RECORD ANALYSIS (MODEL_SOLVED) ==="
python3 .agents/skills/build-cyberbench-task/scripts/workflow.py \
  --manifest tasksets/v3/incoming/generated/batch_1/001/.task-factory-runtime/task-factory.toml \
  record-analysis --file tasksets/v3/incoming/generated/batch_1/001/.task-factory-runtime/workflow/analysis.json 2>&1 | \
  python3 -c 'import sys,json; d=json.load(sys.stdin); print("classification:", d.get("overall_classification"))'

echo ""
echo "=== Task revision changed — re-validate ==="
python3 .agents/skills/build-cyberbench-task/scripts/workflow.py \
  --manifest tasksets/v3/incoming/generated/batch_1/001/.task-factory-runtime/task-factory.toml validate 2>&1 | \
  python3 -c 'import sys,json; d=json.load(sys.stdin); print("passed:",d["passed"]); [print(" ",c["name"],c["passed"]) for c in d["checks"]]'

echo ""
echo "=== Re-run oracle ==="
python3 .agents/skills/build-cyberbench-task/scripts/workflow.py \
  --manifest tasksets/v3/incoming/generated/batch_1/001/.task-factory-runtime/task-factory.toml oracle 2>&1 | \
  python3 -c 'import sys,json; d=json.load(sys.stdin); t=d["trials"][0]; print("reward:",t.get("reward"),"solved:",t.get("solved"),"exc:",(t.get("exception_info") or {}).get("exception_type","none"))'

echo ""
echo "=== Re-record fairness ==="
# Strip BOM from fairness.json if needed.
sed -i '1s/^\xEF\xBB\xBF//' "$REPO/tasksets/v3/incoming/generated/batch_1/001/.task-factory-runtime/workflow/fairness.json"
python3 .agents/skills/build-cyberbench-task/scripts/workflow.py \
  --manifest tasksets/v3/incoming/generated/batch_1/001/.task-factory-runtime/task-factory.toml \
  record-fairness --file tasksets/v3/incoming/generated/batch_1/001/.task-factory-runtime/workflow/fairness.json 2>&1 | \
  python3 -c 'import sys,json; d=json.load(sys.stdin); print("verdict:",d.get("verdict"))'

echo ""
echo "=== Re-record disclosure ==="
sed -i '1s/^\xEF\xBB\xBF//' "$REPO/tasksets/v3/incoming/generated/batch_1/001/.task-factory-runtime/workflow/disclosure.json"
python3 .agents/skills/build-cyberbench-task/scripts/workflow.py \
  --manifest tasksets/v3/incoming/generated/batch_1/001/.task-factory-runtime/task-factory.toml \
  record-disclosure --file tasksets/v3/incoming/generated/batch_1/001/.task-factory-runtime/workflow/disclosure.json \
  --reviewer-kind isolated_agent 2>&1 | \
  python3 -c 'import sys,json; d=json.load(sys.stdin); print("verdict:",d.get("verdict"))'

echo ""
echo "=== STATUS ==="
python3 .agents/skills/build-cyberbench-task/scripts/workflow.py \
  --manifest tasksets/v3/incoming/generated/batch_1/001/.task-factory-runtime/task-factory.toml status 2>&1 | \
  python3 -c '
import sys,json
d=json.load(sys.stdin)
print("phase:", d["phase"])
print("frozen:", d.get("frozen_hash") is not None)
print("fairness:", (d.get("fairness") or {}).get("verdict","none"))
print("disclosure:", (d.get("disclosure") or {}).get("verdict","none"))
print("calibration trials:", len(d["jobs"]["calibration"]))
print("spent:", d["spent_usd"])
'
