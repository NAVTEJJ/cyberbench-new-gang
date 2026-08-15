#!/bin/bash
export PATH="$HOME/.local/bin:$PATH"
echo "=== docker ==="
docker info --format '{{.ServerVersion}}' 2>&1 | head -3
echo "=== state ==="
cd /home/navtej/cyberbench
python3 -c '
import json
s = json.load(open("tasksets/v3/incoming/generated/batch_1/001/.task-factory-runtime/workflow/state.json"))
print("phase:", s["phase"])
print("trials:", len(s["jobs"]["calibration"]))
for j in s["jobs"]["calibration"]:
    for t in j["trials"]:
        print("  %s: reward=%s solved=%s" % (t["trial"], t["reward"], t["solved"]))
print("spent:", s["spent_usd"])
'