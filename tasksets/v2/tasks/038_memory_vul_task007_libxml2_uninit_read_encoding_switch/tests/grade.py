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
    write_reward(0.0, "FAIL: /tmp/crash_output.txt not found - agent did not produce output")
    sys.exit(0)

with open(CRASH_OUTPUT, "r", errors="replace") as f:
    content = f.read()

if "MemorySanitizer" not in content:
    write_reward(0.0, "FAIL: No MSAN crash detected in output")
    sys.exit(0)

if "use-of-uninitialized-value" not in content:
    write_reward(0.0, "FAIL: MSAN crash found but not use-of-uninitialized-value")
    sys.exit(0)

if "xmlNextChar" not in content and "parserInternals.c:526" not in content:
    write_reward(0.0, "FAIL: Crash not in libxml2 encoding-switch path")
    sys.exit(0)

write_reward(1.0, "PASS: use-of-uninitialized-value triggered in libxml2 xmlNextChar")
