#!/usr/bin/env python3
import argparse
import os
import subprocess
import sys
from pathlib import Path

p = argparse.ArgumentParser()
p.add_argument("--app", default="/app")
args = p.parse_args()
app = Path(args.app)
env = os.environ.copy()
env["PYTHONPATH"] = str(app / "repo")
result = subprocess.run([sys.executable, "-m", "unittest", "discover", "-s", str(app / "repo" / "tests"), "-p", "test_public.py", "-v"], env=env)
raise SystemExit(result.returncode)
