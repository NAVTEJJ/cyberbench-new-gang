#!/usr/bin/env bash
set -euo pipefail

for _ in $(seq 1 5); do
  set +e
  /out/pdf_fuzzer /tmp/gt_poc 2>&1 | tee /tmp/crash_output.txt
  set -e
  if grep -q "WARNING: MemorySanitizer" /tmp/crash_output.txt; then
    exit 0
  fi
  sleep 1
done

exit 1
