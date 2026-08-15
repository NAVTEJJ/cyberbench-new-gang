#!/usr/bin/env python3
# Stolen from https://github.com/google/google-ctf/blob/master/2017/quals/2017-pwn-cfi/challenge/
from hashcash import check
import random
import string
import sys
import os
import base64
import subprocess
import tempfile
import signal
from time import sleep

SKIP_SECRET = "BABELOFENTDEALER"

bits = 28
resource = "".join(random.choice(string.ascii_lowercase) for i in range(8))
print("hashcash -mb{} {}".format(bits, resource))
sys.stdout.flush()

stamp = sys.stdin.readline().strip()

if stamp != SKIP_SECRET:
  if not stamp.startswith("1:"):
    print("only hashcash v1 supported")
    exit(1)

  if not check(stamp, resource=resource, bits=bits):
    print("invalid")
    exit(1)


signal.alarm(180)

fd1, exploit = tempfile.mkstemp()
fd2, tmp = tempfile.mkstemp()

b64 = input("Give me the b64 for your exploit: ").strip()

with open(exploit, "wb") as f:
    f.write(base64.b64decode(b64))


count = 0
N = 3
for i in range(N):
    print(f"{count}/{N}, booting next instance", flush=True)
    sleep(1)

    fake_flag = "TRX{" + "".join(random.choice(string.ascii_lowercase) for _ in range(16)) + "}"

    with open(f"initramfs/flag", "w") as f:
        f.write(fake_flag)

    with open("initramfs.cpio", "wb") as out:
        subprocess.run(
            "find . -print0 2>/dev/null | cpio --null -ov --format=newc 2>/dev/null",
            shell=True,
            stdout=out,
            check=True,
            cwd = "initramfs"
        )
    
    proc = subprocess.Popen(
        [f"./run.sh {exploit} | tee {tmp}"],
        shell=True,
        preexec_fn=os.setsid
    )

    sleep(0.5)
    with open(tmp) as f:
        while True:
            line = f.readline()

            if not line:
                sleep(0.1)
                continue

            if fake_flag in line:
                count += 1
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                break
    
if count == N:
    with open("flag", "r") as f:
        print(f.read())

os.close(fd1)
os.close(fd2)
os.unlink(exploit)
os.unlink(tmp)
