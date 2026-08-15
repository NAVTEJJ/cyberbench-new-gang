import pathlib
import shutil

bak = pathlib.Path("/home/navtej/.local/lib/python3.12/site-packages/harbor/trial/artifact_handler.py.bak")
dst = pathlib.Path("/home/navtej/.local/lib/python3.12/site-packages/harbor/trial/artifact_handler.py")

# Read backup content
content = bak.read_text()

# Write to target 
dst.write_text(content)

# Also clear any .pyc cache
import importlib
pyc_dir = pathlib.Path("/home/navtej/.local/lib/python3.12/site-packages/harbor/trial/__pycache__")
if pyc_dir.exists():
    for f in pyc_dir.glob("artifact_handler*.pyc"):
        f.unlink()
        print(f"Removed cache: {f}")

# Verify the relevant section
lines = content.split('\n')
for i, line in enumerate(lines):
    if 'has_contents' in line or (line.strip() == 'try:' and len(line) - len(line.lstrip()) == 8 and i > 360 and i < 375):
        print(f"  {i+1}: {repr(line)}")

print("Restored from backup")
