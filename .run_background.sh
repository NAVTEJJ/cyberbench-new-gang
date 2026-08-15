#!/bin/bash
cd /mnt/c/Users/NAVTEJ/Downloads/Cyber-Bench-main
export PATH="$HOME/.local/bin:$PATH"
MANIFEST="tasksets/v3/incoming/generated/batch_1/009/.task-factory-runtime/task-factory.toml"
SCRIPT=".agents/skills/build-cyberbench-task/scripts/workflow.py"
nohup python3 "$SCRIPT" --manifest "$MANIFEST" run-target --attempts 1 > /mnt/c/Users/NAVTEJ/Downloads/Cyber-Bench-main/tasksets/v3/incoming/generated/batch_1/009/.task-factory-runtime/workflow/run_target_v2.log 2>&1 &
echo "PID: $!"
echo "Started background target run"
