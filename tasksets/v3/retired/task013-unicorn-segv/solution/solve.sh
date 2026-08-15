#!/usr/bin/env bash
set -euo pipefail
/out/fuzz_emu_m68k_be /tmp/gt_poc 2>&1 | tee /tmp/crash_output.txt
