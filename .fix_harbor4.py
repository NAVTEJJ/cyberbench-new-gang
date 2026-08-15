import pathlib

p = pathlib.Path("/home/navtej/.local/lib/python3.12/site-packages/harbor/trial/artifact_handler.py")
content = p.read_text()
lines = content.split('\n')

# Find and fix the broken section
# Current broken state: try: has 12 spaces, should have 8
new_lines = []
i = 0
while i < len(lines):
    line = lines[i]
    stripped = line.lstrip()
    indent = len(line) - len(stripped)
    
    # Fix the try: that has 12 spaces (should have 8) in the has_contents section
    if stripped == 'try:' and indent == 12 and i + 1 < len(lines):
        next_line = lines[i + 1]
        if 'has_contents = target.exists()' in next_line:
            # This is the broken try: - fix it to 8 spaces
            new_lines.append('        try:')
            i += 1
            continue
    
    new_lines.append(line)
    i += 1

content = '\n'.join(new_lines)
p.write_text(content)

# Verify
lines2 = content.split('\n')
for j, line in enumerate(lines2):
    if 'has_contents = target.exists()' in line:
        start = max(0, j - 3)
        end = min(len(lines2), j + 5)
        print("Fixed section:")
        for k in range(start, end):
            indent = len(lines2[k]) - len(lines2[k].lstrip())
            print(f"  {k+1}: indent={indent} {repr(lines2[k])}")
        break

# Clear pyc cache
pyc_dir = pathlib.Path("/home/navtej/.local/lib/python3.12/site-packages/harbor/trial/__pycache__")
if pyc_dir.exists():
    for f in pyc_dir.glob("artifact_handler*.pyc"):
        f.unlink()

# Test import
try:
    import harbor.trial.artifact_handler
    print("Import OK")
except Exception as e:
    print(f"Import failed: {e}")
