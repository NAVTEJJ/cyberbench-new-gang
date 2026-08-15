#!/usr/bin/env python3
import argparse
import importlib.util
import json
import os
from pathlib import Path

p = argparse.ArgumentParser()
p.add_argument("--app", default="/app")
args = p.parse_args()
app = Path(args.app)
os.environ["APP_DIR"] = str(app)
spec = importlib.util.spec_from_file_location("candidate_detector", app / "detector.py")
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
scenarios = json.loads((app / "data" / "dev_scenarios.json").read_text())["scenarios"]
families = ["device_code_takeover", "ci_secret_exfil", "service_account_lateral"]
stats = {f: {"tp": 0, "fp": 0, "fn": 0} for f in families}
rows = []
for scenario in scenarios:
    alerts = mod.detect(scenario["events"])
    predicted = {a.get("family") for a in alerts if isinstance(a, dict)} if isinstance(alerts, list) else set()
    expected = scenario["label"]
    for family in families:
        positive = expected == family
        hit = family in predicted
        stats[family]["tp"] += int(positive and hit)
        stats[family]["fp"] += int(not positive and hit)
        stats[family]["fn"] += int(positive and not hit)
    rows.append({"scenario_id": scenario["scenario_id"], "expected": expected, "predicted": sorted(x for x in predicted if x)})
for family, s in stats.items():
    precision = s["tp"] / max(1, s["tp"] + s["fp"])
    recall = s["tp"] / max(1, s["tp"] + s["fn"])
    s["precision"] = round(precision, 3)
    s["recall"] = round(recall, 3)
print(json.dumps({"per_family": stats, "scenarios": rows}, indent=2, sort_keys=True))
