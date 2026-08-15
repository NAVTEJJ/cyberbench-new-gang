#!/usr/bin/env sh
set -eu
mkdir -p /logs/verifier
python3 /tests/grade_flags.py
