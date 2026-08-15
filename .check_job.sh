#!/bin/bash
LATEST=$(ls -td /mnt/c/Users/NAVTEJ/Downloads/Cyber-Bench-main/tasksets/v3/incoming/generated/batch_1/009/.task-factory-runtime/jobs/split_ws_header_l0_target_* 2>/dev/null | head -1)
echo "Latest target job: $LATEST"
cat "$LATEST/result.json" 2>&1
echo ""
echo "---"
ls "$LATEST"/*/verifier/details.json 2>/dev/null && cat "$LATEST"/*/verifier/details.json 2>/dev/null || echo "No verifier details yet"
echo "---"
# Check if Harbor is still running
ps aux | grep "harbor.*009" | grep -v grep | head -3
