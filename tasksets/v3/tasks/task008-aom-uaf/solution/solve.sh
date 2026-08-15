#!/usr/bin/env bash
set -euo pipefail
/out/av1_dec_fuzzer /tmp/gt_poc 2>&1 | tee /tmp/crash_output.txt
