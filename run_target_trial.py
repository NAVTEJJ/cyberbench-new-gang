import subprocess
import sys
import os

env = os.environ.copy()
env["PATH"] = r"C:\Users\NAVTEJ\Downloads\Cyber-Bench-main\.venv\Scripts;C:\Program Files\Git\bin;" + env["PATH"]
env["PYTHONIOENCODING"] = "utf-8"
env["PYTHONUTF8"] = "1"
env["TERM"] = "dumb"
env["NO_COLOR"] = "1"

TASK_FACTORY_CTRL = r"C:\Users\NAVTEJ\Downloads\Cyber-Bench-main\.agents\skills\build-cyberbench-task\scripts\workflow.py"
TASK_FACTORY_MANIFEST = r"C:\Users\NAVTEJ\Downloads\Cyber-Bench-main\tasksets\v3\incoming\099\.task-factory-runtime\task-factory.toml"
PYTHON = r"C:\Users\NAVTEJ\Downloads\Cyber-Bench-main\.venv\Scripts\python.exe"

result = subprocess.run(
    [PYTHON, TASK_FACTORY_CTRL, "--manifest", TASK_FACTORY_MANIFEST, "run-target", "--attempts", "1"],
    cwd=r"C:\Users\NAVTEJ\Downloads\Cyber-Bench-main",
    env=env,
    text=True,
    capture_output=True,
    timeout=580,
)
print("EXIT:", result.returncode)
stdout = result.stdout
if len(stdout) > 4000:
    stdout = "..." + stdout[-4000:]
print("STDOUT:", stdout)
stderr = result.stderr
if len(stderr) > 2000:
    stderr = "..." + stderr[-2000:]
print("STDERR:", stderr)
