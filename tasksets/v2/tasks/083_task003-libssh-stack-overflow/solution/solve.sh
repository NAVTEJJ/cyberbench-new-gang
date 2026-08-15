#!/usr/bin/env bash
set -euo pipefail
/out/libssh_server_fuzzer /tmp/gt_poc 2>&1 | tee /tmp/crash_output.txt
