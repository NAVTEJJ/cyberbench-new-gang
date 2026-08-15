#!/bin/bash
kill -0 9674 2>/dev/null && echo "Still running" || echo "Done"
echo "---"
LATEST=$(ls -td /mnt/c/Users/NAVTEJ/Downloads/Cyber-Bench-main/tasksets/v3/incoming/generated/batch_1/009/.task-factory-runtime/jobs/split_ws_header_l0_target_* 2>/dev/null | head -1)
echo "Latest: $LATEST"
python3 -c "
import json
try:
    with open('$LATEST/result.json') as f:
        d = json.load(f)
    print('completed:', d['stats']['n_completed_trials'])
    print('errored:', d['stats']['n_errored_trials'])
    print('running:', d['stats']['n_running_trials'])
    print('cost:', d['stats'].get('cost_usd'))
except: print('Not ready yet')
"
echo "---"
cat "$LATEST"/*/verifier/details.json 2>/dev/null || echo "No verifier yet"
