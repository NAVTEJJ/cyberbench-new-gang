#!/bin/bash
cd /mnt/c/Users/NAVTEJ/Downloads/Cyber-Bench-main
export PATH="$HOME/.local/bin:$PATH"
MANIFEST="tasksets/v3/incoming/generated/batch_1/009/.task-factory-runtime/task-factory.toml"
SCRIPT=".agents/skills/build-cyberbench-task/scripts/workflow.py"
LOGFILE="tasksets/v3/incoming/generated/batch_1/009/.task-factory-runtime/workflow/run_target_trial3.log"

setsid python3 "$SCRIPT" --manifest "$MANIFEST" run-target --attempts 1 > "$LOGFILE" 2>&1 &
PID=$!
echo "PID: $PID"
echo "Log: $LOGFILE"
sleep 5
if kill -0 $PID 2>/dev/null; then
    echo "Process is running"
else
    echo "Process exited"
    cat "$LOGFILE"
fi
