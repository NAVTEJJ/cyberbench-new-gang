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

TASK_FACTORY_CTRL = r"C:\Users\NAVTEJ\Downloads\Cyber-Bench-main\.agents\skills\build-cyberbench-task\scripts\workflow.py"
TASK_FACTORY_MANIFEST = r"C:\Users\NAVTEJ\Downloads\Cyber-Bench-main\tasksets\v3\incoming\099\.task-factory-runtime\task-factory.toml"
PYTHON = r"C:\Users\NAVTEJ\Downloads\Cyber-Bench-main\.venv\Scripts\python.exe"

# Launch detached
proc = subprocess.Popen(
    [PYTHON, TASK_FACTORY_CTRL, "--manifest", TASK_FACTORY_MANIFEST, "run-target", "--attempts", "3"],
    cwd=r"C:\Users\NAVTEJ\Downloads\Cyber-Bench-main",
    env=env,
    text=True,
    stdout=open(r"C:\Users\NAVTEJ\Downloads\Cyber-Bench-main\target_run_stdout.txt", "w"),
    stderr=open(r"C:\Users\NAVTEJ\Downloads\Cyber-Bench-main\target_run_stderr.txt", "w"),
    creationflags=subprocess.DETACHED_PROCESS if sys.platform == "win32" else 0,
)

print(f"Started detached process PID={proc.pid}")
print("Polling for completion...")

# Poll for up to 25 minutes
for i in range(150):
    time.sleep(10)
    ret = proc.poll()
    if ret is not None:
        print(f"Process completed with exit code {ret} after {i*10}s")
        break
    if i % 6 == 0:
        print(f"  Still running after {i*10}s...")
else:
    print("Timed out waiting for process")
    proc.kill()

# Print results
try:
    with open(r"C:\Users\NAVTEJ\Downloads\Cyber-Bench-main\target_run_stdout.txt", "r") as f:
        stdout = f.read()
    if len(stdout) > 4000:
        stdout = "..." + stdout[-4000:]
    print("STDOUT:", stdout)
except:
    pass

try:
    with open(r"C:\Users\NAVTEJ\Downloads\Cyber-Bench-main\target_run_stderr.txt", "r") as f:
        stderr = f.read()
    if len(stderr) > 2000:
        stderr = "..." + stderr[-2000:]
    print("STDERR:", stderr)
except:
    pass
