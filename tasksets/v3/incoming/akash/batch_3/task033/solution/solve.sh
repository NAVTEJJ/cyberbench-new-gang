#!/bin/bash
set -e
OUT_DIR="${OUT_DIR:-/src}"
if ! mkdir -p "$OUT_DIR" 2>/dev/null; then OUT_DIR="."; fi
export OUT_DIR
python3 - <<'INNER_PY'
from pathlib import Path
import os
Path(os.environ['OUT_DIR'],'request.resp').write_bytes(b'*2\r\n$3\r\nGET\r\n$4\r\nsafe\r\n*2\r\n$6\r\nCONFIG\r\n$3\r\nGET\r\n$11\r\nrequirepass\r\n')
INNER_PY
