#!/bin/bash
set -e
export PATH="$HOME/.local/bin:$PATH"
cd /mnt/c/Users/NAVTEJ/Downloads/Cyber-Bench-main
echo "=== bash -n checks ==="
bash -n tasksets/v3/incoming/generated/batch_1/001/ctr_relay_l0/solution/solve.sh && echo "solve.sh OK"
bash -n tasksets/v3/incoming/generated/batch_1/001/ctr_relay_l0/tests/test.sh && echo "test.sh OK"
echo "=== py_compile ==="
python3 -m py_compile \
  tasksets/v3/incoming/generated/batch_1/001/ctr_relay_l0/environment/assets/ctr-relay/app.py \
  tasksets/v3/incoming/generated/batch_1/001/ctr_relay_l0/environment/gateway.py \
  tasksets/v3/incoming/generated/batch_1/001/ctr_relay_l0/tests/grade_flags.py && echo "py_compile OK"
echo "=== docker compose config ==="
docker compose -f tasksets/v3/incoming/generated/batch_1/001/ctr_relay_l0/environment/docker-compose.yaml config --quiet && echo "compose OK"
echo "=== controller validate ==="
python3 .agents/skills/build-cyberbench-task/scripts/workflow.py \
  --manifest tasksets/v3/incoming/generated/batch_1/001/.task-factory-runtime/task-factory.toml validate 2>&1 | python3 -c "import sys,json; d=json.load(sys.stdin); print('passed:', d['passed']); [print(' ', c['name'], c['passed']) for c in d['checks']]"
