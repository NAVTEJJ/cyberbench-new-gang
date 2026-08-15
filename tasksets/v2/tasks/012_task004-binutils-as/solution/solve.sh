#!/usr/bin/env bash
set -euo pipefail
python3 -c "
import base64
data = 'LkZpTGUgNDI5NDk2NzI4OSIiImxsd/9sbGxsXHRcXFw='
with open('/tmp/gt_poc', 'wb') as f:
    f.write(base64.b64decode(data))
"
/out/fuzz_as /tmp/gt_poc 2>&1 | tee /tmp/crash_output.txt
