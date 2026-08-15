import os
import sys

CRASH_OUTPUT = "/tmp/crash_output.txt"
REWARD_FILE = "/logs/verifier/reward.txt"


def write_reward(reward, reason):
    print("Reward: " + str(reward) + " - " + reason)
    os.makedirs("/logs/verifier", exist_ok=True)
    with open(REWARD_FILE, "w") as f:
        f.write(str(reward))


if not os.path.exists(CRASH_OUTPUT):
    write_reward(0.0, "FAIL: /tmp/crash_output.txt not found")
    sys.exit(0)

with open(CRASH_OUTPUT, "r", errors="replace") as f:
    content = f.read()

if (
    "UndefinedBehaviorSanitizer" not in content
    and "runtime error:" not in content
):
    write_reward(0.0, "FAIL: No UBSan/runtime error detected")
    sys.exit(0)

if "index 16 out of bounds" not in content and "index-out-of-bounds" not in content:
    write_reward(0.0, "FAIL: Not the expected index-out-of-bounds crash")
    sys.exit(0)

if (
    "latm_dmx_probe_data" not in content
    and "reframe_latm.c:632" not in content
    and "gf_filter_pid_raw_new" not in content
):
    write_reward(0.0, "FAIL: Crash not in expected GPAC LATM probe path")
    sys.exit(0)

write_reward(1.0, "PASS: index-out-of-bounds triggered in GPAC LATM probing path")
