#!/bin/bash
cp /home/navtej/.local/lib/python3.12/site-packages/harbor/trial/artifact_handler.py /home/navtej/.local/lib/python3.12/site-packages/harbor/trial/artifact_handler.py.bak

python3 << 'PYEOF'
import pathlib
p = pathlib.Path("/home/navtej/.local/lib/python3.12/site-packages/harbor/trial/artifact_handler.py")
content = p.read_text()
old = "        has_contents = target.exists() and any(target.iterdir())"
new = """        try:
            has_contents = target.exists() and any(target.iterdir())
        except OSError:
            has_contents = True"""
content = content.replace(old, new, 1)
p.write_text(content)
print("Patched successfully")
PYEOF

sed -n '366,374p' /home/navtej/.local/lib/python3.12/site-packages/harbor/trial/artifact_handler.py
