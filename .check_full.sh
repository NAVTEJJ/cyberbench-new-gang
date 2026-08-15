#!/bin/bash
LATEST=$(ls -td /mnt/c/Users/NAVTEJ/Downloads/Cyber-Bench-main/tasksets/v3/incoming/generated/batch_1/009/.task-factory-runtime/jobs/split_ws_header_l0_target_* 2>/dev/null | head -1)
echo "Latest: $LATEST"
echo "=== Last 20 lines of job.log ==="
tail -20 "$LATEST/job.log" 2>&1
echo ""
echo "=== Docker containers ==="
docker ps --filter name=split_ws 2>&1 | head -5
echo ""
echo "=== Process status ==="
kill -0 58178 2>/dev/null && echo "Process running" || echo "Process done"
echo "=== Harbor processes ==="
ps aux | grep "harbor.*009" | grep -v grep | head -3
