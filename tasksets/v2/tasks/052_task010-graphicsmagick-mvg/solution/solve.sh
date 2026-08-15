#!/usr/bin/env bash
set -euo pipefail
/out/coder_MVG_fuzzer /tmp/gt_poc 2>&1 | tee /tmp/crash_output.txt
