#!/usr/bin/env python3
import json
from datetime import datetime, timezone
from pathlib import Path


def parse_time(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)


base = Path(__file__).resolve().parents[1] / "evidence" / "telemetry"
for path in sorted(base.glob("*.jsonl")):
    previous_offset = None
    for line in path.read_text().splitlines():
        event = json.loads(line)
        if event.get("event_type") == "time_sync":
            offset = int((parse_time(event["reported_ts"]) - parse_time(event["trusted_utc"])).total_seconds())
            change = "initial sample" if previous_offset is None else f"change={offset - previous_offset:+d}s"
            print(
                f"{event['source']}: reported_ts={event['reported_ts']} "
                f"trusted_utc={event['trusted_utc']} offset={offset:+d}s ({change})"
            )
            previous_offset = offset
