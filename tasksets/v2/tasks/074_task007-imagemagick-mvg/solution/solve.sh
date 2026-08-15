#!/usr/bin/env bash
set -euo pipefail
/out/encoder_mvg_fuzzer /tmp/gt_poc 2>&1 | tee /tmp/crash_output.txt
