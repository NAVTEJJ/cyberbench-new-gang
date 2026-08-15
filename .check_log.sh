#!/bin/bash
LATEST=$(ls -td /mnt/c/Users/NAVTEJ/Downloads/Cyber-Bench-main/tasksets/v3/incoming/generated/batch_1/009/.task-factory-runtime/jobs/split_ws_header_l0_target_* 2>/dev/null | head -1)
echo "Latest: $LATEST"
tail -30 "$LATEST/job.log" 2>&1
