#!/bin/bash
export PATH="$HOME/.local/bin:$PATH"
cd /home/navtej/cyberbench

echo "=== running containers ==="
docker ps --format "{{.Names}} {{.Status}}" 2>&1 | head -10

echo "=== harbor processes ==="
ps aux | grep -i "harbor\|workflow" | grep -v grep 2>&1

echo "=== state ==="
python3 -c '
import json
s = json.load(open("tasksets/v3/incoming/generated/batch_1/001/.task-factory-runtime/workflow/state.json"))
print("phase:", s["phase"])
print("trials:", len(s["jobs"]["calibration"]))
for j in s["jobs"]["calibration"]:
    for t in j["trials"]:
        print("  %s: reward=%s solved=%s cost=%s" % (t["trial"], t["reward"], t["solved"], t["cost_usd"]))
print("spent:", s["spent_usd"])
'