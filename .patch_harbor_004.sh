#!/bin/bash
set -e

HARBOR_FILE="$HOME/.local/lib/python3.12/site-packages/harbor/trial/artifact_handler.py"

if [ ! -f "$HARBOR_FILE" ]; then
    echo "Harbor artifact_handler.py not found at $HARBOR_FILE"
    # Try to find it
    FOUND=$(python3 -c "import harbor.trial.artifact_handler as a; print(a.__file__)" 2>/dev/null || true)
    if [ -n "$FOUND" ]; then
        HARBOR_FILE="$FOUND"
        echo "Found at: $HARBOR_FILE"
    else
        echo "Cannot find harbor installation"
        exit 0
    fi
fi

# Check if already patched
if grep -q "except OSError" "$HARBOR_FILE" 2>/dev/null; then
    echo "Already patched"
    exit 0
fi

# Backup
cp "$HARBOR_FILE" "${HARBOR_FILE}.bak"

# Patch
python3 << 'PYEOF'
import pathlib
import sys

p = pathlib.Path(sys.argv[1]) if len(sys.argv) > 1 else None
if p is None:
    import harbor.trial.artifact_handler as a
    p = pathlib.Path(a.__file__)

content = p.read_text()
old = "        has_contents = target.exists() and any(target.iterdir())"
new = """        try:
            has_contents = target.exists() and any(target.iterdir())
        except OSError:
            has_contents = True"""

if old in content:
    content = content.replace(old, new, 1)
    p.write_text(content)
    print(f"Patched successfully: {p}")
else:
    print(f"Pattern not found in {p} - may already be patched or different version")
    # Show the surrounding code for debugging
    lines = content.split('\n')
    for i, line in enumerate(lines):
        if 'has_contents' in line:
            start = max(0, i-2)
            end = min(len(lines), i+3)
            print(f"\nContext around line {i+1}:")
            for j in range(start, end):
                print(f"  {j+1}: {lines[j]}")
PYEOF
