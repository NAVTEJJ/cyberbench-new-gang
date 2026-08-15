#!/usr/bin/env python3
import argparse
import datetime as dt
import json
from pathlib import Path


p = argparse.ArgumentParser()
p.add_argument("--app", default="/app")
p.add_argument("--key", required=True)
p.add_argument("--at", required=True)
args = p.parse_args()

cutoff = dt.datetime.fromisoformat(args.at.replace("Z", "+00:00"))
events = []
path = Path(args.app) / "trust" / "key_events.jsonl"
for line in path.read_text().splitlines():
    event = json.loads(line)
    when = dt.datetime.fromisoformat(event["utc"].replace("Z", "+00:00"))
    if event["key_id"] == args.key and when <= cutoff:
        events.append(event)
print(json.dumps({"events_at_or_before": events, "key_id": args.key, "timestamp": args.at}, indent=2, sort_keys=True))
