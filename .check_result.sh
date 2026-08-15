#!/bin/bash
LATEST=$(ls -td /mnt/c/Users/NAVTEJ/Downloads/Cyber-Bench-main/tasksets/v3/incoming/generated/batch_1/009/.task-factory-runtime/jobs/split_ws_header_l0_target_* 2>/dev/null | head -1)
echo "Latest: $LATEST"
echo "=== result.json ==="
cat "$LATEST/result.json" 2>&1
echo ""
echo "=== verifier details ==="
cat "$LATEST"/*/verifier/details.json 2>&1
echo ""
echo "=== process status ==="
kill -0 58178 2>/dev/null && echo "Process still running" || echo "Process done"
