#!/usr/bin/env python3
"""Package a Cyber-Bench Harbor task directory into a zip with forward-slash
paths and executable bits set on shell scripts.

Usage:
    python3 package_task.py <task_dir> [-o output.zip]
    python3 package_task.py tasksets/v3/incoming/generated/batch_1/004/unicode_escape_binstack_l0

The resulting zip uses POSIX path separators (forward slashes) so it extracts
correctly on Linux, and marks .sh files as executable (Unix mode 0o755).
"""
from __future__ import annotations

import argparse
import os
import stat
import sys
import zipfile
from pathlib import Path


EXECUTABLE_EXTENSIONS = {".sh"}
EXECUTABLE_NAMES = {"solve.sh", "test.sh", "grade_flags.py", "grader.py", "grade.py"}

# Harbor's oracle/verifier agents exec .sh scripts directly (kernel parses the
# shebang line) rather than via `bash script.sh`. A CRLF-terminated shebang
# (`#!/usr/bin/env bash\r\n`) makes the kernel look for an interpreter literally
# named "bash\r", which fails with "bad interpreter: No such file or directory"
# on every Linux host regardless of which machine built or unzipped the task.
# Authoring on Windows (plain `open(..., "w")`) writes CRLF by default, so
# normalize these to LF unconditionally at packaging time rather than relying
# on the source tree already being clean.
NORMALIZE_EOL_EXTENSIONS = {".sh"}


def should_be_executable(path: Path) -> bool:
    return path.suffix in EXECUTABLE_EXTENSIONS or path.name in EXECUTABLE_NAMES


def read_file_bytes(path: Path) -> bytes:
    data = path.read_bytes()
    if path.suffix in NORMALIZE_EOL_EXTENSIONS:
        data = data.replace(b"\r\n", b"\n").replace(b"\r", b"\n")
    return data


def create_task_zip(task_dir: Path, output: Path) -> None:
    if not task_dir.is_dir():
        raise SystemExit(f"task directory not found: {task_dir}")

    skip_dirs = {".task-factory-runtime", "__pycache__", ".git"}
    files: list[Path] = []
    for root, dirs, filenames in os.walk(task_dir):
        dirs[:] = sorted(d for d in dirs if d not in skip_dirs)
        for filename in sorted(filenames):
            files.append(Path(root) / filename)

    output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as zf:
        for filepath in files:
            arcname = filepath.relative_to(task_dir).as_posix()
            info = zipfile.ZipInfo.from_file(filepath, arcname)
            if should_be_executable(filepath):
                info.external_attr = (stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH) << 16
            else:
                info.external_attr = (stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH) << 16
            zf.writestr(info, read_file_bytes(filepath))

    print(f"Created {output} ({len(files)} files)")


def verify_zip(output: Path) -> None:
    with zipfile.ZipFile(output, "r") as zf:
        issues: list[str] = []
        for info in zf.infolist():
            if "\\" in info.filename:
                issues.append(f"backslash in path: {info.filename}")
            if info.filename.endswith((".sh",)) or info.filename.endswith(("solve.sh", "test.sh")):
                mode = (info.external_attr >> 16) & 0o777
                if mode & 0o111 == 0:
                    issues.append(f"not executable: {info.filename} (mode={oct(mode)})")
                if b"\r" in zf.read(info.filename):
                    issues.append(f"CRLF line endings (breaks shebang exec on Linux): {info.filename}")
        if issues:
            print("VERIFICATION ISSUES:", file=sys.stderr)
            for issue in issues:
                print(f"  {issue}", file=sys.stderr)
            raise SystemExit(1)
        print(f"Verified {output}: all paths use forward slashes, scripts are executable")


def main() -> int:
    parser = argparse.ArgumentParser(description="Package a Harbor task into a portable zip")
    parser.add_argument("task_dir", type=Path, help="Path to the task directory")
    parser.add_argument("-o", "--output", type=Path, default=None, help="Output zip path")
    parser.add_argument("--verify", action="store_true", help="Verify the zip after creation")
    args = parser.parse_args()

    task_dir = args.task_dir.resolve()
    output = args.output or task_dir.with_suffix(".zip")
    create_task_zip(task_dir, output)
    if args.verify:
        verify_zip(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())