#!/usr/bin/env bash
set -eu
python3 -c "
import base64
data = 'iVBORw0KGgoAAAANSUhEUgAAACAAACAgEAAAAAAgICAgAAAABklEQVQY02OmDSA='
with open('/tmp/gt_poc', 'wb') as f:
    f.write(base64.b64decode(data))
"
/out/libpng_read_fuzzer /tmp/gt_poc 2>&1 | tee /tmp/crash_output.txt
