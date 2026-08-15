import pathlib

p = pathlib.Path("/home/navtej/.local/lib/python3.12/site-packages/harbor/trial/artifact_handler.py")
content = p.read_text()

# The broken section looks like:
#         try:
#             try:
#             has_contents = target.exists() and any(target.iterdir())
#         except OSError:
#             has_contents = True
#         except OSError:
#             has_contents = True
#
# Replace with:
#         try:
#             has_contents = target.exists() and any(target.iterdir())
#         except OSError:
#             has_contents = True

broken = """        try:
            try:
            has_contents = target.exists() and any(target.iterdir())
        except OSError:
            has_contents = True
        except OSError:
            has_contents = True"""

fixed = """        try:
            has_contents = target.exists() and any(target.iterdir())
        except OSError:
            has_contents = True"""

if broken in content:
    content = content.replace(broken, fixed, 1)
    p.write_text(content)
    print("Fixed broken section")
else:
    print("Broken section not found - checking for other patterns")
    # Try a more flexible approach: find lines around has_contents
    lines = content.split('\n')
    for i, line in enumerate(lines):
        if 'has_contents = target.exists()' in line:
            # Show context
            start = max(0, i - 5)
            end = min(len(lines), i + 8)
            print(f"Context around line {i+1}:")
            for j in range(start, end):
                print(f"  {j+1}: {repr(lines[j])}")
            
            # Rebuild the section
            # Find the function def line (with -> ArtifactManifestEntry:)
            func_line = None
            for k in range(i, max(0, i-20), -1):
                if 'ArtifactManifestEntry:' in lines[k]:
                    func_line = k
                    break
            
            if func_line is not None:
                # Find the return line after has_contents
                return_line = None
                for k in range(i+1, min(len(lines), i+10)):
                    if 'return ArtifactManifestEntry(' in lines[k]:
                        return_line = k
                        break
                
                if return_line is not None:
                    # Replace everything between func_line+1 and return_line
                    new_section = [
                        '        try:',
                        '            has_contents = target.exists() and any(target.iterdir())',
                        '        except OSError:',
                        '            has_contents = True',
                    ]
                    new_lines = lines[:func_line+1] + new_section + lines[return_line:]
                    content = '\n'.join(new_lines)
                    p.write_text(content)
                    print(f"Rebuilt section between lines {func_line+1} and {return_line}")
            break

# Verify
content2 = p.read_text()
lines2 = content2.split('\n')
for i, line in enumerate(lines2):
    if 'has_contents = target.exists()' in line:
        start = max(0, i - 3)
        end = min(len(lines2), i + 5)
        print(f"\nVerification around line {i+1}:")
        for j in range(start, end):
            print(f"  {j+1}: {repr(lines2[j])}")
        break

# Clear pyc cache
pyc_dir = pathlib.Path("/home/navtej/.local/lib/python3.12/site-packages/harbor/trial/__pycache__")
if pyc_dir.exists():
    for f in pyc_dir.glob("artifact_handler*.pyc"):
        f.unlink()
        print(f"Removed cache: {f}")
