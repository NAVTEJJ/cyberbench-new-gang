import pathlib

p = pathlib.Path("/home/navtej/.local/lib/python3.12/site-packages/harbor/trial/artifact_handler.py")
content = p.read_text()

# Find and fix the broken section
# The broken section has multiple try: statements and misindented has_contents
lines = content.split('\n')

# Find the line with "has_contents = target.exists()"
for i, line in enumerate(lines):
    if 'has_contents = target.exists() and any(target.iterdir())' in line:
        print(f"Found has_contents at line {i+1}")
        # Show surrounding context
        start = max(0, i-5)
        end = min(len(lines), i+5)
        for j in range(start, end):
            print(f"  {j+1}: {repr(lines[j])}")
        break

# Remove extra try: lines and fix indentation
new_lines = []
skip_extra_try = True
for i, line in enumerate(lines):
    stripped = line.lstrip()
    indent = len(line) - len(stripped)
    
    # Fix the broken section: remove extra try: lines and fix has_contents indentation
    if stripped == 'try:' and indent == 8 and skip_extra_try:
        # Keep the first try: at indent 8
        new_lines.append(line)
        skip_extra_try = False
        continue
    elif stripped == 'try:' and indent >= 12:
        # Skip extra try: lines
        continue
    elif 'has_contents = target.exists()' in line and indent == 12:
        # Fix indentation to 16 (inside try block at indent 12)
        new_lines.append('            ' + line.lstrip())
        continue
    elif stripped == 'except OSError:' and indent == 8:
        # Skip duplicate except blocks
        if not any(l.lstrip() == 'except OSError:' for l in new_lines[-3:]):
            new_lines.append(line)
        continue
    elif 'has_contents = True' in line and indent == 12:
        # Keep only one has_contents = True
        if not any('has_contents = True' in l for l in new_lines[-3:]):
            new_lines.append(line)
        continue
    else:
        new_lines.append(line)
        if stripped == 'return ArtifactManifestEntry(':
            skip_extra_try = True  # Reset for next function

content_fixed = '\n'.join(new_lines)
p.write_text(content_fixed)
print("Fixed artifact_handler.py")

# Verify
for i, line in enumerate(content_fixed.split('\n')):
    if 'has_contents' in line or (line.strip() == 'try:' and len(line) - len(line.lstrip()) == 8):
        print(f"  {i+1}: {repr(line)}")
