#!/bin/bash
cd /mnt/c/Users/NAVTEJ/Downloads/Cyber-Bench-main
export PATH="$HOME/.local/bin:$PATH"
MANIFEST="tasksets/v3/incoming/generated/batch_1/004/.task-factory-runtime/task-factory.toml"
SCRIPT=".agents/skills/build-cyberbench-task/scripts/workflow.py"
LOGFILE="tasksets/v3/incoming/generated/batch_1/004/.task-factory-runtime/target_run.log"

python3 "$SCRIPT" --manifest "$MANIFEST" run-target --attempts 1 > "$LOGFILE" 2>&1
echo "EXIT_CODE=$?" >> "$LOGFILE"
