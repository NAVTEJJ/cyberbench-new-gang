#!/usr/bin/env python3
from __future__ import annotations

import json
import os
from pathlib import Path

CRASH_OUTPUT = "/tmp/crash_output.txt"
LOG_DIR = Path("/logs/verifier")


def write_reward(reward: float, reason: str) -> None:
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    (LOG_DIR / "reward.txt").write_text(f"{reward}\n")
    (LOG_DIR / "reward.json").write_text(json.dumps({"reward": reward}, indent=2) + "\n")
    details = {
        "reward": reward,
        "reason": reason,
        "crash_type": "double-free",
        "sanitizer": "asan",
        "program": "kvstore_cmd",
    }
    (LOG_DIR / "details.json").write_text(json.dumps(details, indent=2, sort_keys=True) + "\n")
    print(f"Reward: {reward} - {reason}")


if not os.path.exists(CRASH_OUTPUT):
    write_reward(0.0, "FAIL: /tmp/crash_output.txt not found")
    raise SystemExit(0)

with open(CRASH_OUTPUT, "r", errors="replace") as f:
    content = f.read()

if "AddressSanitizer" not in content:
    write_reward(0.0, "FAIL: No AddressSanitizer crash detected in output")
    raise SystemExit(0)

if "double-free" not in content:
    write_reward(0.0, "FAIL: ASan crash found but not a double-free")
    raise SystemExit(0)

write_reward(1.0, "PASS: double-free triggered in kvstore_cmd")