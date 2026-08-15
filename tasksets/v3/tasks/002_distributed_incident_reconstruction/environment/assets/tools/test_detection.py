#!/usr/bin/env python3
import argparse
import json
from pathlib import Path

from simulation_engine import evaluate_detection, read_json


parser = argparse.ArgumentParser(description="Replay a sequence detection against public scenarios.")
parser.add_argument("rule", nargs="?", default="/app/detection.json")
parser.add_argument("--scenarios", default=str(Path(__file__).resolve().parents[1] / "evidence" / "simulator" / "detection_scenarios.json"))
args = parser.parse_args()

try:
    result = evaluate_detection(read_json(args.rule), read_json(args.scenarios))
except (OSError, ValueError, json.JSONDecodeError) as exc:
    result = {"passed": False, "errors": [str(exc)], "scenarios": []}
print(json.dumps(result, indent=2, sort_keys=True))
raise SystemExit(0 if result["passed"] else 1)
