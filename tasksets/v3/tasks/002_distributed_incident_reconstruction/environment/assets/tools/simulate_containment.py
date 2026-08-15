#!/usr/bin/env python3
import argparse
import json
from pathlib import Path

from simulation_engine import load_telemetry, read_json, simulate_containment


parser = argparse.ArgumentParser(description="Evaluate containment against attacker and business workflows.")
parser.add_argument("plan", nargs="?", default="/app/containment_actions.json")
parser.add_argument("--context", default=str(Path(__file__).resolve().parents[1] / "evidence" / "simulator" / "containment_scenarios.json"))
parser.add_argument("--incident", default="/app/incident.json")
parser.add_argument("--telemetry", default=str(Path(__file__).resolve().parents[1] / "evidence" / "telemetry"))
args = parser.parse_args()

try:
    result = simulate_containment(
        read_json(args.plan),
        read_json(args.context),
        read_json(args.incident),
        load_telemetry(args.telemetry),
    )
except (OSError, ValueError, json.JSONDecodeError) as exc:
    result = {"passed": False, "errors": [str(exc)]}
print(json.dumps(result, indent=2, sort_keys=True))
raise SystemExit(0 if result["passed"] else 1)
