#!/usr/bin/env bash
set -eu
python3 -c "
import base64
data = 'ICAgICAgICAtMTZFLTEwNjE5NDcwNjU='
with open('/tmp/gt_poc', 'wb') as f:
    f.write(base64.b64decode(data))
"
/out/jq_fuzz_parse_extended /tmp/gt_poc 2>&1 | tee /tmp/crash_output.txt
