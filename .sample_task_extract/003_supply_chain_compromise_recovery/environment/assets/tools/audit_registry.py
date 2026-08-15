#!/usr/bin/env python3
import argparse
import json
from pathlib import Path
from libregistry import locked_packages, package_metadata, source_digest, package_dir

p = argparse.ArgumentParser()
p.add_argument("--app", default="/app")
p.add_argument("--name", required=True)
p.add_argument("--version", required=True)
args = p.parse_args()
app = Path(args.app)
meta = package_metadata(app, args.name, args.version)
source = package_dir(app, args.name, args.version) / "package.py"
lock = next((item for item in locked_packages(app) if item["name"] == args.name and item["version"] == args.version), None)
print(json.dumps({
    "actual_source_sha256": source_digest(source),
    "lock_entry": lock,
    "registry_metadata": meta,
}, indent=2, sort_keys=True))
