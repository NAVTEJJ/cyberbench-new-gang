import os
import sys
import subprocess

REWARD_FILE = "/logs/verifier/reward.txt"

def write_reward(reward, reason):
    print("Reward: " + str(reward) + " - " + reason)
    os.makedirs("/logs/verifier", exist_ok=True)
    with open(REWARD_FILE, "w") as f:
        f.write(str(reward))

print("Compiling Ring-LWE NTT Cryptography Bench...")
build = subprocess.run(["gcc", "-O2", "-Wall", "-Werror", "-fsanitize=address,undefined", "-o", "/out/ntt_bench", "/src/target.c"], capture_output=True)
if build.returncode != 0:
    write_reward(0.0, "FAIL: Compilation failed")
    sys.exit(0)

print("Running Ring-LWE NTT Cryptography Tests...")
run = subprocess.run(["/out/ntt_bench"], capture_output=True, text=True)
if run.returncode == 0 and "FLAG: Post-Quantum Ring-LWE NTT Cryptography Success!" in run.stdout:
    write_reward(1.0, "PASS: Ring-LWE NTT engine correctly performed polynomial multiplication and decryption homomorphism")
else:
    write_reward(0.0, "FAIL: Ring-LWE NTT engine failed homomorphism, produced noise errors, or crashed under AddressSanitizer/UBSAN")
