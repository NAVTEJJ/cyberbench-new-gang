#!/usr/bin/env python3
import argparse
import json
from pathlib import Path
from libregistry import build_vendor

p = argparse.ArgumentParser()
p.add_argument("--app", default="/app")
p.add_argument("--scenario")
args = p.parse_args()
app = Path(args.app)
scenarios = json.loads((app / "workspace" / "build_scenarios.json").read_text())
scenario_name = args.scenario or scenarios["default"]
if scenario_name not in scenarios["scenarios"]:
    raise SystemExit(f"unknown scenario {scenario_name!r}; choose from {sorted(scenarios['scenarios'])}")
records = build_vendor(app, scenario_name=scenario_name)
extension_runs = []
for record in records:
    extension_runs.extend(record.pop("extension_results", []))
(app / "workspace" / "build_manifest.json").write_text(
    json.dumps(
        {
            "scenario": scenario_name,
            "packages": records,
            "extension_runs": extension_runs,
        },
        indent=2,
        sort_keys=True,
    ) + "\n"
)
print(json.dumps({
    "scenario": scenario_name,
    "built": [f'{x["name"]}=={x["version"]}' for x in records],
}, indent=2))
