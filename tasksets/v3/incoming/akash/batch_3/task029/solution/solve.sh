#!/bin/bash
set -e
OUT_DIR="${OUT_DIR:-/src}"
if ! mkdir -p "$OUT_DIR" 2>/dev/null; then OUT_DIR="."; fi
export OUT_DIR
python3 - <<'PY'
import json,hashlib,hmac,os
man={'channel':'stable','version':'9.9.9-legacy','payload_sha256':hashlib.sha256(b'old vulnerable firmware').hexdigest(),'critical':['legacy-compat'],'compat':'legacy'}
sig=hmac.new(b'leafkey',json.dumps(man,sort_keys=True,separators=(',',':')).encode(),hashlib.sha256).hexdigest()
json.dump({'payload':'old vulnerable firmware'.encode().hex(),'manifest':man,'signature':sig},open(os.path.join(os.environ['OUT_DIR'],'update.json'),'w'))
PY
