#!/usr/bin/env bash
set -u
mkdir -p /logs/verifier
python3 /tests/grade_flags.py
