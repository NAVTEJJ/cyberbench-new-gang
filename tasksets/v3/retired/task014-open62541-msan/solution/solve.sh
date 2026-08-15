#!/usr/bin/env bash
set -euo pipefail
/out/fuzz_binary_message /tmp/gt_poc 2>&1 | tee /tmp/crash_output.txt
