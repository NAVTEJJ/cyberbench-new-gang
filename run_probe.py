import subprocess
import sys
import os
import time

env = os.environ.copy()
env["PATH"] = r"C:\Users\NAVTEJ\Downloads\Cyber-Bench-main\.venv\Scripts;C:\Program Files\Git\bin;" + env["PATH"]
env["PYTHONIOENCODING"] = "utf-8"
env["PYTHONUTF8"] = "1"
env["TERM"] = "dumb"
env["NO_COLOR"] = "1"

PYTHON = r"C:\Users\NAVTEJ\Downloads\Cyber-Bench-main\.venv\Scripts\python.exe"
TASK_FACTORY_CTRL = r"C:\Users\NAVTEJ\Downloads\Cyber-Bench-main\.agents\skills\build-cyberbench-task\scripts\workflow.py"
TASK_FACTORY_MANIFEST = r"C:\Users\NAVTEJ\Downloads\Cyber-Bench-main\tasksets\v3\incoming\100\.task-factory-runtime\task-factory.toml"
CWD = r"C:\Users\NAVTEJ\Downloads\Cyber-Bench-main"

stdout_file = open(r"C:\Users\NAVTEJ\AppData\Local\Temp\opencode\target_out.txt", "w")
stderr_file = open(r"C:\Users\NAVTEJ\AppData\Local\Temp\opencode\target_err.txt", "w")

proc = subprocess.Popen(
    [PYTHON, TASK_FACTORY_CTRL, "--manifest", TASK_FACTORY_MANIFEST, "run-target", "--attempts", "1"],
    cwd=CWD,
    env=env,
    stdout=stdout_file,
    stderr=stderr_file,
    creationflags=0x00000008,  # DETACHED_PROCESS
)

print(f"Started detached PID={proc.pid}")

for i in range(180):
    time.sleep(10)
    ret = proc.poll()
    if ret is not None:
        print(f"Process finished with exit code {ret} after {(i+1)*10}s")
        break
    if i % 6 == 0:
        print(f"  Still running after {(i+1)*10}s...")
else:
    print("Timed out after 30 minutes")
    proc.kill()

stdout_file.close()
stderr_file.close()

with open(r"C:\Users\NAVTEJ\AppData\Local\Temp\opencode\target_out.txt", "r") as f:
    content = f.read()
if len(content) > 4000:
    content = "..." + content[-4000:]
print("STDOUT:", content)

with open(r"C:\Users\NAVTEJ\AppData\Local\Temp\opencode\target_err.txt", "r") as f:
    err = f.read()
if len(err) > 2000:
    err = "..." + err[-2000:]
if err:
    print("STDERR:", err)
