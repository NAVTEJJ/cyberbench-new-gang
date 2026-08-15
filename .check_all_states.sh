#!/bin/bash
for ws in 004 005 006 007 008 009 010; do
  dir="/mnt/c/Users/NAVTEJ/Downloads/Cyber-Bench-main/tasksets/v3/incoming/generated/batch_1/$ws"
  statefile="$dir/.task-factory-runtime/workflow/state.json"
  if [ -f "$statefile" ]; then
    python3 -c "
import json, sys
s = json.load(open('$statefile'))
phase = s.get('phase', '?')
iteration = s.get('iteration', 0)
spent = s.get('spent_usd', 0)
oracle_jobs = len(s.get('jobs', {}).get('oracle', []))
target_jobs = len(s.get('jobs', {}).get('calibration', []))
frozen = s.get('frozen_hash') is not None
print(f'WS $ws: phase={phase} iter={iteration} spent=\${spent} oracle={oracle_jobs} target={target_jobs} frozen={frozen}')
"
  else
    echo "WS $ws: no state file"
  fi
done