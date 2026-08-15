#!/bin/bash
export PATH="$HOME/.local/bin:$PATH"
sleep 600
echo "=== trial1.log ==="
cat /tmp/trial1.log 2>&1 | tail -30
echo "=== state ==="
cd /home/navtej/cyberbench
python3 -c '
import json
s = json.load(open("tasksets/v3/incoming/generated/batch_1/001/.task-factory-runtime/workflow/state.json"))
print("trials:", len(s["jobs"]["calibration"]))
for j in s["jobs"]["calibration"]:
    for t in j["trials"]:
        print("  %s: reward=%s solved=%s cost=%s" % (t["trial"], t["reward"], t["solved"], t["cost_usd"]))
print("spent:", s["spent_usd"])
print("phase:", s["phase"])
'
echo "=== docker ==="
docker ps --format "{{.Names}} {{.Status}}" 2>&1 | grep ctr_relay | head -5