#!/bin/bash
cd /mnt/c/Users/NAVTEJ/Downloads/Cyber-Bench-main
export PATH="$HOME/.local/bin:$PATH"
MANIFEST="tasksets/v3/incoming/generated/batch_1/006/.task-factory-runtime/task-factory.toml"
SCRIPT=".agents/skills/build-cyberbench-task/scripts/workflow.py"
CMD="${1:-init}"
shift 2>/dev/null || true
EXTRA_ARGS="$@"
python3 "$SCRIPT" --manifest "$MANIFEST" "$CMD" $EXTRA_ARGS
