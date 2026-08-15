#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "$0")" && pwd)"
base64 -d "$script_dir/gt_poc.b64" > /tmp/gt_poc
/out/av1_dec_fuzzer /tmp/gt_poc 2>&1 | tee /tmp/crash_output.txt
