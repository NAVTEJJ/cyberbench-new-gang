#!/bin/bash
set -euo pipefail
mkdir -p "${LOG_DIR:-/logs/verifier}"
python3 /tests/grader.py
